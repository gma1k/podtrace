package agent

import (
	"reflect"
	"testing"

	"github.com/gma1k/podtrace/internal/inspect"
)

func TestEveryThresholdTheRulesReadIsPopulatedAtRuntime(t *testing.T) {
	got := inspectionThresholds()
	defaults := inspect.DefaultThresholds()

	gv := reflect.ValueOf(got)
	dv := reflect.ValueOf(defaults)
	typ := gv.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Name == "HoldTime" || field.Name == "HoldTimes" {
			continue
		}
		if !dv.Field(i).IsZero() && gv.Field(i).IsZero() {
			t.Errorf("inspectionThresholds() leaves %s at its zero value while "+
				"DefaultThresholds() sets %v.\n\nThresholds.unset() only substitutes the "+
				"shipped defaults when *every* field is zero, so one omitted field is not "+
				"backfilled -- it reaches the rule as zero. For a threshold a value is "+
				"compared against, zero means the rule fires on everything, and nothing "+
				"in the unit tests notices because they construct DefaultThresholds() "+
				"directly.", field.Name, dv.Field(i).Interface())
		}
	}
}

func TestRuntimeThresholdsMatchTheShippedDefaults(t *testing.T) {
	got := inspectionThresholds()
	defaults := inspect.DefaultThresholds()

	if got.AcquireMean != defaults.AcquireMean {
		t.Errorf("AcquireMean = %v at runtime, defaults say %v", got.AcquireMean, defaults.AcquireMean)
	}
	if got.MeanLatency != defaults.MeanLatency {
		t.Errorf("MeanLatency = %v at runtime, defaults say %v", got.MeanLatency, defaults.MeanLatency)
	}
	if got.ErrorRatePercent != defaults.ErrorRatePercent {
		t.Errorf("ErrorRatePercent = %v at runtime, defaults say %v",
			got.ErrorRatePercent, defaults.ErrorRatePercent)
	}
}
