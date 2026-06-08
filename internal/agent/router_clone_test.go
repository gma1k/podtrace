package agent

import "testing"

func TestClonePolicySnapshot_Empty(t *testing.T) {
	out := clonePolicySnapshot(PolicySnapshot{Hash: "h", Generation: 7})
	if out.Hash != "h" || out.Generation != 7 {
		t.Errorf("scalar fields not copied: %+v", out)
	}
	if out.EffectiveSamplePercent != nil || out.Filters != nil || out.Thresholds != nil {
		t.Errorf("nil pointers/slices should remain nil: %+v", out)
	}
}

func TestClonePolicySnapshot_DeepCopiesAllFields(t *testing.T) {
	in := PolicySnapshot{
		EffectiveSamplePercent: i32p(50),
		Filters:                []string{"a", "b"},
		Thresholds: &PolicyThresholds{
			ErrorRatePercent: i32p(5),
			RTTSpikeMs:       i32p(100),
			FSSlowMs:         i32p(20),
		},
		Hash:       "abc",
		Generation: 3,
	}
	out := clonePolicySnapshot(in)

	*in.EffectiveSamplePercent = 99
	in.Filters[0] = "mutated"
	*in.Thresholds.ErrorRatePercent = 99
	*in.Thresholds.RTTSpikeMs = 999
	*in.Thresholds.FSSlowMs = 999

	if out.EffectiveSamplePercent == nil || *out.EffectiveSamplePercent != 50 {
		t.Errorf("EffectiveSamplePercent aliased; got %v", out.EffectiveSamplePercent)
	}
	if out.Filters[0] != "a" {
		t.Errorf("Filters aliased; got %v", out.Filters)
	}
	if out.Thresholds == nil {
		t.Fatal("Thresholds should be non-nil")
	}
	if *out.Thresholds.ErrorRatePercent != 5 {
		t.Errorf("ErrorRatePercent aliased; got %d", *out.Thresholds.ErrorRatePercent)
	}
	if *out.Thresholds.RTTSpikeMs != 100 {
		t.Errorf("RTTSpikeMs aliased; got %d", *out.Thresholds.RTTSpikeMs)
	}
	if *out.Thresholds.FSSlowMs != 20 {
		t.Errorf("FSSlowMs aliased; got %d", *out.Thresholds.FSSlowMs)
	}
}

func TestClonePolicySnapshot_ThresholdsWithNilFields(t *testing.T) {
	in := PolicySnapshot{Thresholds: &PolicyThresholds{}}
	out := clonePolicySnapshot(in)
	if out.Thresholds == nil {
		t.Fatal("Thresholds should be cloned even when fields are nil")
	}
	if out.Thresholds == in.Thresholds {
		t.Error("Thresholds should be a distinct pointer")
	}
	if out.Thresholds.ErrorRatePercent != nil || out.Thresholds.RTTSpikeMs != nil || out.Thresholds.FSSlowMs != nil {
		t.Error("inner pointers should stay nil")
	}
}
