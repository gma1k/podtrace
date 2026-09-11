package operator

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/config"
)

func TestInspectionsEnvEmitsNothingWhenAbsentOrDisabled(t *testing.T) {
	for name, spec := range map[string]*podtracev1alpha1.AgentInspectionsSpec{
		"nil":      nil,
		"disabled": {Enabled: false},
		"disabled with thresholds set": {
			Enabled: false,
			Thresholds: &podtracev1alpha1.AgentInspectionThresholdsSpec{
				ErrorRatePercent: ptr(int32(1)),
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := inspectionsEnv(spec); len(got) != 0 {
				t.Errorf("got %v, want no env; a disabled half must leave the pod template "+
					"byte-identical so it triggers no rollout", envMap(got))
			}
		})
	}
}

func TestInspectionsEnvReachesTheAgentThroughTheMetricsSpec(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled: true,
		Inspections: &podtracev1alpha1.AgentInspectionsSpec{
			Enabled: true,
		},
	}))
	if got[envInspectionsEnabled] != "true" {
		t.Errorf("%s = %q, want true; the CRD field would be silently inert",
			envInspectionsEnabled, got[envInspectionsEnabled])
	}

	off := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled: false,
		Inspections: &podtracev1alpha1.AgentInspectionsSpec{
			Enabled: true,
		},
	}))
	if _, present := off[envInspectionsEnabled]; present {
		t.Error("inspections were enabled with the metrics plane off; every rule would " +
			"evaluate over an empty surface and always report healthy")
	}
}

func TestEveryInspectionFieldIsTranslated(t *testing.T) {
	got := envMap(inspectionsEnv(&podtracev1alpha1.AgentInspectionsSpec{
		Enabled:  true,
		Interval: &metav1.Duration{Duration: 90 * time.Second},
		Alerts:   ptr(false),
		Budget:   ptr(int32(64)),
		Thresholds: &podtracev1alpha1.AgentInspectionThresholdsSpec{
			ErrorRatePercent:     ptr(int32(3)),
			MinRequestsPerMinute: ptr(int32(30)),
			MeanLatency:          &metav1.Duration{Duration: 250 * time.Millisecond},
			AcquireMean:          &metav1.Duration{Duration: 75 * time.Millisecond},
		},
	}))

	for name, want := range map[string]string{
		envInspectionsEnabled:    "true",
		envInspectionsInterval:   "1m30s",
		envInspectionsAlerts:     "false",
		envInspectionsBudget:     "64",
		envInspectionErrorRate:   "3",
		envInspectionMinRequests: "0.5",
		envInspectionMeanLatency: "250ms",
		envInspectionAcquireMean: "75ms",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
}

func TestEveryTranslatedValueIsParsedBackByTheAgent(t *testing.T) {
	env := envMap(inspectionsEnv(&podtracev1alpha1.AgentInspectionsSpec{
		Enabled:  true,
		Interval: &metav1.Duration{Duration: 45 * time.Second},
		Budget:   ptr(int32(7)),
		Thresholds: &podtracev1alpha1.AgentInspectionThresholdsSpec{
			ErrorRatePercent:     ptr(int32(12)),
			MinRequestsPerMinute: ptr(int32(1)),
			MeanLatency:          &metav1.Duration{Duration: 1500 * time.Millisecond},
			AcquireMean:          &metav1.Duration{Duration: 900 * time.Millisecond},
		},
	}))

	for _, name := range []string{envInspectionsInterval, envInspectionMeanLatency, envInspectionAcquireMean} {
		if _, err := time.ParseDuration(env[name]); err != nil {
			t.Errorf("%s = %q, which the agent's duration parser rejects: %v",
				name, env[name], err)
		}
	}

	got, ok := config.ParseNonNegativeFloat(env[envInspectionMinRequests])
	if !ok || got != 1.0/60 {
		t.Errorf("%s = %q round-tripped to %v (ok=%v), want 1/60",
			envInspectionMinRequests, env[envInspectionMinRequests], got, ok)
	}
}

func TestAZeroOrNegativeIntervalIsLeftToTheAgentDefault(t *testing.T) {
	got := envMap(inspectionsEnv(&podtracev1alpha1.AgentInspectionsSpec{
		Enabled:  true,
		Interval: &metav1.Duration{Duration: 0},
		Thresholds: &podtracev1alpha1.AgentInspectionThresholdsSpec{
			MeanLatency: &metav1.Duration{Duration: 0},
		},
	}))
	for _, name := range []string{envInspectionsInterval, envInspectionMeanLatency, envInspectionAcquireMean} {
		if _, present := got[name]; present {
			t.Errorf("%s was emitted as %q; a zero interval would spin the loop",
				name, got[name])
		}
	}
}

func TestHoldTimeReachesTheAgentEnv(t *testing.T) {
	got := envMap(inspectionsEnv(&podtracev1alpha1.AgentInspectionsSpec{
		Enabled:  true,
		HoldTime: &metav1.Duration{Duration: 20 * time.Second},
	}))
	if got[envInspectionsHoldTime] != "20s" {
		t.Errorf("%s = %q, want 20s; the CRD field would be inert",
			envInspectionsHoldTime, got[envInspectionsHoldTime])
	}
	if _, err := time.ParseDuration(got[envInspectionsHoldTime]); err != nil {
		t.Errorf("the agent's duration parser rejects %q: %v",
			got[envInspectionsHoldTime], err)
	}
}

func TestAZeroHoldTimeIsLeftToTheRuleDefaults(t *testing.T) {
	for name, spec := range map[string]*podtracev1alpha1.AgentInspectionsSpec{
		"absent": {Enabled: true},
		"zero":   {Enabled: true, HoldTime: &metav1.Duration{Duration: 0}},
	} {
		t.Run(name, func(t *testing.T) {
			got := envMap(inspectionsEnv(spec))
			if _, present := got[envInspectionsHoldTime]; present {
				t.Errorf("%s was emitted as %q; a zero hold would fire on a single "+
					"interval's blip", envInspectionsHoldTime, got[envInspectionsHoldTime])
			}
		})
	}
}

func TestEveryThresholdFieldOnTheCRDReachesTheAgent(t *testing.T) {
	spec := &podtracev1alpha1.AgentInspectionThresholdsSpec{}
	v := reflect.ValueOf(spec).Elem()
	typ := v.Type()

	for i := 0; i < typ.NumField(); i++ {
		switch v.Field(i).Type().String() {
		case "*int32":
			v.Field(i).Set(reflect.ValueOf(ptr(int32(7))))
		case "*v1.Duration":
			v.Field(i).Set(reflect.ValueOf(&metav1.Duration{Duration: 7 * time.Second}))
		default:
			t.Fatalf("field %s has unhandled type %s; teach this guard about it",
				typ.Field(i).Name, v.Field(i).Type())
		}
	}

	got := envMap(inspectionsEnv(&podtracev1alpha1.AgentInspectionsSpec{
		Enabled:    true,
		Thresholds: spec,
	}))

	if len(got)-1 != typ.NumField() {
		t.Errorf("%d threshold fields are set but inspectionsEnv emitted %d variables "+
			"besides the enabled flag: %v\n\nA field added to the CRD without a matching "+
			"branch in inspectionsEnv is accepted by the API server, stored, and then "+
			"silently dropped on the way to the agent, which runs the shipped default "+
			"while the CR says otherwise.", typ.NumField(), len(got)-1, got)
	}
}
