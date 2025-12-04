package tracker

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestConnectionTracker_ProcessEventAndSummary(t *testing.T) {
	ct := NewConnectionTracker()
	now := time.Now()

	connect := &events.Event{
		Type:      events.EventConnect,
		Target:    "example.com",
		Error:     0,
		Timestamp: uint64(now.UnixNano()),
	}
	send := &events.Event{
		Type:      events.EventTCPSend,
		Target:    "example.com",
		LatencyNS: uint64(time.Millisecond * 10),
		Timestamp: uint64(now.Add(time.Millisecond).UnixNano()),
	}
	recv := &events.Event{
		Type:      events.EventTCPRecv,
		Target:    "example.com",
		LatencyNS: uint64(time.Millisecond * 5),
		Timestamp: uint64(now.Add(2 * time.Millisecond).UnixNano()),
	}

	ct.ProcessEvent(connect)
	ct.ProcessEvent(send)
	ct.ProcessEvent(recv)

	summaries := ct.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].TotalOps != 2 {
		t.Fatalf("expected 2 total ops, got %d", summaries[0].TotalOps)
	}
}

func TestGenerateConnectionCorrelation(t *testing.T) {
	now := time.Now()
	evs := []*events.Event{
		{
			Type:      events.EventConnect,
			Target:    "example.com",
			Error:     0,
			Timestamp: uint64(now.UnixNano()),
		},
		{
			Type:      events.EventTCPSend,
			Target:    "example.com",
			LatencyNS: uint64(time.Millisecond * 10),
			Timestamp: uint64(now.Add(time.Millisecond).UnixNano()),
		},
	}

	report := GenerateConnectionCorrelation(evs)
	if report == "" {
		t.Fatalf("expected non-empty correlation report")
	}
}
