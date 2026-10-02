package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/events"
)

type fakeStamper struct {
	calls int
	err   error
}

func (f *fakeStamper) StampRequests() error {
	f.calls++
	return f.err
}

func TestADiagnoseRunAsksTheTracerToStampRequests(t *testing.T) {
	ok := &fakeStamper{}
	stampRequests(ok)
	if ok.calls != 1 {
		t.Errorf("StampRequests called %d times", ok.calls)
	}
	failing := &fakeStamper{err: errors.New("no map")}
	stampRequests(failing)
	if failing.calls != 1 {
		t.Errorf("a failing stamper was not asked: %d", failing.calls)
	}
	stampRequests(struct{}{})
}

func TestARequestDonePassesEveryCategoryFilter(t *testing.T) {
	in := make(chan *events.Event, 2)
	out := make(chan *events.Event, 2)
	in <- &events.Event{Type: events.EventRequestDone}
	in <- &events.Event{Type: events.EventRead}
	close(in)
	go filterEvents(context.Background(), in, out, "net")

	var got []events.EventType
	for ev := range out {
		got = append(got, ev.Type)
	}
	if len(got) != 1 || got[0] != events.EventRequestDone {
		t.Errorf("a net filter passed %v; without the request-done no request is ever finished", got)
	}
}

func TestTheDiagnoseReportEndsWithTheRequestBreakdown(t *testing.T) {
	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(eventForPod("ns", "only-pod"))
	d.AddEvent(&events.Event{Type: events.EventTCPRecv, CorrelationID: 9, Timestamp: 40_000_000, LatencyNS: 30_000_000})
	d.AddEvent(&events.Event{Type: events.EventRequestDone, CorrelationID: 9, Timestamp: 50_000_000, LatencyNS: 50_000_000})
	d.Finish()

	report := generateDiagnoseReport(d)
	if !strings.Contains(report, "Request Time Breakdown:") || !strings.Contains(report, "network 60.0%") {
		t.Errorf("report lacks the breakdown:\n%s", report)
	}
}
