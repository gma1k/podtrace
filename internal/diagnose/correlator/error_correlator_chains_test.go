package correlator

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestErrorChainKey_Precedence(t *testing.T) {
	cases := []struct {
		name string
		ev   *ErrorEvent
		want string
	}{
		{"target wins", &ErrorEvent{Target: "10.0.0.1:80", Context: map[string]string{"target_pod": "p"}}, "t:10.0.0.1:80"},
		{"pod when no target", &ErrorEvent{Context: map[string]string{"target_pod": "p"}}, "p:p"},
		{"service when no target or pod", &ErrorEvent{Context: map[string]string{"target_service": "svc"}}, "s:svc"},
		{"empty when nothing", &ErrorEvent{Context: map[string]string{}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorChainKey(tc.ev); got != tc.want {
				t.Errorf("errorChainKey() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildChains_SkipsErrorsWithoutIdentifier(t *testing.T) {
	ec := NewErrorCorrelator(30 * time.Second)
	base := time.Now()
	ec.errors = []*ErrorEvent{
		{ErrorCode: -111, Timestamp: base, Context: map[string]string{}},
		{ErrorCode: -111, Timestamp: base.Add(time.Second), Context: map[string]string{}},
	}
	ec.buildChains()
	if len(ec.chains) != 0 {
		t.Errorf("errors with no identifier must not be chained, got %d chains", len(ec.chains))
	}
}

func TestBuildChains_ChainsGroupedByPodAndService(t *testing.T) {
	ec := NewErrorCorrelator(30 * time.Second)
	base := time.Now()
	ec.errors = []*ErrorEvent{
		{ErrorCode: -111, Timestamp: base, Context: map[string]string{"target_pod": "pod-a"}},
		{ErrorCode: -11, Timestamp: base.Add(time.Second), Context: map[string]string{"target_pod": "pod-a"}},
		{ErrorCode: -110, Timestamp: base.Add(2 * time.Second), Context: map[string]string{"target_service": "svc-b"}},
		{ErrorCode: -110, Timestamp: base.Add(3 * time.Second), Context: map[string]string{"target_service": "svc-b"}},
	}
	ec.buildChains()
	if len(ec.chains) != 2 {
		t.Fatalf("expected 2 chains (pod-a, svc-b), got %d", len(ec.chains))
	}
	if !ec.chains[0].RootCause.Timestamp.Before(ec.chains[1].RootCause.Timestamp) {
		t.Error("chains must be sorted by root-cause timestamp ascending")
	}
}

func TestAddEvent_EvictsBeyondRetentionCap(t *testing.T) {
	ec := NewErrorCorrelator(30 * time.Second)
	ts := uint64(time.Now().UnixNano())
	for i := 0; i < maxRetainedErrors+50; i++ {
		ec.AddEvent(&events.Event{
			Type:      events.EventConnect,
			Target:    "10.0.0.1:8080",
			Error:     -111,
			Timestamp: ts,
		}, nil)
	}
	if len(ec.errors) != maxRetainedErrors {
		t.Errorf("error buffer = %d, want it bounded at %d", len(ec.errors), maxRetainedErrors)
	}
}
