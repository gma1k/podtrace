package v1alpha1

import (
	"context"
	"strings"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestEmbeddedBTFModeWarnsThatItIsNotImplemented(t *testing.T) {
	v := tracerConfigValidator(t)

	warnings, err := v.ValidateCreate(context.Background(),
		tracerConfig("embedded-btf", podtracev1alpha1.TracerConfigSpec{
			BTFMode: podtracev1alpha1.BTFModeEmbedded,
		}))
	if err != nil {
		t.Fatalf("embedded must stay accepted, not rejected: %v", err)
	}

	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "not implemented") {
		t.Errorf("no warning said the mode is unimplemented, got %v\n\nThe CRD enum "+
			"accepts embedded, so without a warning at apply time nothing tells the "+
			"author the field does nothing; the operator log is not where they are "+
			"looking.", warnings)
	}
}

func TestAutoAndHostBTFModesWarnAboutNothing(t *testing.T) {
	for _, mode := range []podtracev1alpha1.BTFMode{
		"",
		podtracev1alpha1.BTFModeAuto,
		podtracev1alpha1.BTFModeHost,
	} {
		v := tracerConfigValidator(t)
		warnings, err := v.ValidateCreate(context.Background(),
			tracerConfig("btf-"+string(mode)+"x", podtracev1alpha1.TracerConfigSpec{BTFMode: mode}))
		if err != nil {
			t.Fatalf("btfMode %q rejected: %v", mode, err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "btfMode") {
				t.Errorf("btfMode %q produced %q; only the unimplemented mode should warn",
					mode, w)
			}
		}
	}
}

func TestEmbeddedBTFModeStillWarnsWhenThereIsNoClient(t *testing.T) {
	v := &TracerConfigCustomValidator{}

	warnings, err := v.ValidateCreate(context.Background(),
		tracerConfig("embedded-noclient", podtracev1alpha1.TracerConfigSpec{
			BTFMode: podtracev1alpha1.BTFModeEmbedded,
		}))
	if err != nil {
		t.Fatalf("ValidateCreate: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("the warning was dropped on the no-client path.\n\nvalidate() returns " +
			"early when it has no client to list siblings with, and an early return that " +
			"forgets the warning makes the knob silent again in exactly the configurations " +
			"that skip the overlap check.")
	}
}
