package agent

import (
	"testing"

	bundlepkg "github.com/podtrace/podtrace/pkg/exporter/bundle"
)

func i32p(v int32) *int32 { return &v }

func TestPolicyThresholdsFromBundle_Nil(t *testing.T) {
	if got := policyThresholdsFromBundle(nil); got != nil {
		t.Errorf("nil input should yield nil, got %+v", got)
	}
}

func TestPolicyThresholdsFromBundle_AllFields(t *testing.T) {
	in := &bundlepkg.Thresholds{
		ErrorRatePercent: i32p(5),
		RTTSpikeMs:       i32p(120),
		FSSlowMs:         i32p(50),
	}
	got := policyThresholdsFromBundle(in)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.ErrorRatePercent == nil || *got.ErrorRatePercent != 5 {
		t.Errorf("ErrorRatePercent = %v, want 5", got.ErrorRatePercent)
	}
	if got.RTTSpikeMs == nil || *got.RTTSpikeMs != 120 {
		t.Errorf("RTTSpikeMs = %v, want 120", got.RTTSpikeMs)
	}
	if got.FSSlowMs == nil || *got.FSSlowMs != 50 {
		t.Errorf("FSSlowMs = %v, want 50", got.FSSlowMs)
	}
	*in.ErrorRatePercent = 99
	if *got.ErrorRatePercent != 5 {
		t.Error("ErrorRatePercent aliased input pointer; expected a copy")
	}
}

func TestPolicyThresholdsFromBundle_PartialFields(t *testing.T) {
	in := &bundlepkg.Thresholds{RTTSpikeMs: i32p(200)}
	got := policyThresholdsFromBundle(in)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.ErrorRatePercent != nil {
		t.Errorf("ErrorRatePercent should be nil, got %v", *got.ErrorRatePercent)
	}
	if got.RTTSpikeMs == nil || *got.RTTSpikeMs != 200 {
		t.Errorf("RTTSpikeMs = %v, want 200", got.RTTSpikeMs)
	}
	if got.FSSlowMs != nil {
		t.Errorf("FSSlowMs should be nil, got %v", *got.FSSlowMs)
	}
}
