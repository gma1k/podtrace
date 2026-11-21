package diagnose

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestEveryEventReachesTheCriticalPathEvenOnceTheBufferSamples(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 2
	for i := 0; i < 50; i++ {
		d.AddEvent(&events.Event{Type: events.EventTCPRecv, CorrelationID: 7, Timestamp: uint64(1000 + i*10), LatencyNS: 5})
	}
	d.AddEvent(&events.Event{Type: events.EventRequestDone, CorrelationID: 7, Timestamp: 2000, LatencyNS: 1500})

	s := d.CriticalPath()
	if s.Requests != 1 || len(s.Slowest) != 1 {
		t.Fatalf("summary = %+v", s)
	}
	var network uint64
	for _, sh := range s.Slowest[0].Shares {
		if sh.Category == "network" {
			network = uint64(sh.Duration)
		}
	}
	if network != 250 {
		t.Errorf("network = %dns, want all 50 waits of 5ns although the buffer kept 2 events", network)
	}
}

func TestEveryConstructorHasACriticalPath(t *testing.T) {
	for name, d := range map[string]*Diagnostician{
		"plain":            NewDiagnostician(),
		"thresholds":       NewDiagnosticianWithThresholds(1, 1, 1),
		"k8s":              NewDiagnosticianWithK8s("p", "n"),
		"k8s + thresholds": NewDiagnosticianWithK8sAndThresholds("p", "n", 1, 1, 1),
	} {
		d.AddEvent(&events.Event{Type: events.EventRequestDone, CorrelationID: 1, Timestamp: 10, LatencyNS: 5})
		if d.CriticalPath().Requests != 1 {
			t.Errorf("%s: the request was not counted", name)
		}
	}
}

func TestARequestDoneSampledOutOfTheBufferStillReachesTheCriticalPath(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.sampleUniform = rising()
	for i := range 3 {
		d.AddEvent(&events.Event{Type: events.EventRequestDone, CorrelationID: uint64(i + 1), Timestamp: uint64(10 + i), LatencyNS: 5})
	}
	if d.EventsSampledOut() == 0 {
		t.Fatal("the buffer never sampled")
	}
	if got := d.CriticalPath().Requests; got != 3 {
		t.Errorf("critical path counted %d requests, want 3", got)
	}
}
