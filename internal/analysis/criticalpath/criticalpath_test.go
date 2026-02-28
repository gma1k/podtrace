package criticalpath_test

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/analysis/criticalpath"
	"github.com/podtrace/podtrace/internal/events"
)

func makeEvent(t events.EventType, pid uint32, latNS uint64, details string) *events.Event {
	return &events.Event{
		Type:      t,
		PID:       pid,
		LatencyNS: latNS,
		Details:   details,
	}
}

func TestFeed_EmitsOnBoundary(t *testing.T) {
	var got []criticalpath.CriticalPath
	a := criticalpath.New(500*time.Millisecond, func(cp criticalpath.CriticalPath) {
		got = append(got, cp)
	})

	a.Feed(makeEvent(events.EventDBQuery, 42, 5_000_000, "SELECT"))
	a.Feed(makeEvent(events.EventRedisCmd, 42, 1_000_000, "GET"))
	a.Feed(makeEvent(events.EventHTTPResp, 42, 10_000_000, ""))

	if len(got) != 1 {
		t.Fatalf("expected 1 CriticalPath, got %d", len(got))
	}
	cp := got[0]
	if cp.PID != 42 {
		t.Errorf("PID: want 42, got %d", cp.PID)
	}
	if len(cp.Segments) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(cp.Segments))
	}
	totalNS := uint64(cp.TotalLatency)
	if totalNS != 16_000_000 {
		t.Errorf("TotalLatency: want 16ms, got %d ns", totalNS)
	}
	// Fractions should sum to ~1.0
	var sum float64
	for _, s := range cp.Segments {
		sum += s.Fraction
	}
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("fractions should sum to 1.0, got %f", sum)
	}
}

func TestFeed_SeparatesWindowsByPID(t *testing.T) {
	var got []criticalpath.CriticalPath
	a := criticalpath.New(500*time.Millisecond, func(cp criticalpath.CriticalPath) {
		got = append(got, cp)
	})

	a.Feed(makeEvent(events.EventDBQuery, 1, 1_000_000, ""))
	a.Feed(makeEvent(events.EventDBQuery, 2, 2_000_000, ""))
	a.Feed(makeEvent(events.EventHTTPResp, 1, 3_000_000, ""))
	a.Feed(makeEvent(events.EventGRPCMethod, 2, 4_000_000, ""))

	if len(got) != 2 {
		t.Fatalf("expected 2 CriticalPaths, got %d", len(got))
	}
}

func TestFeed_ZeroLatencyIgnored(t *testing.T) {
	var got []criticalpath.CriticalPath
	a := criticalpath.New(500*time.Millisecond, func(cp criticalpath.CriticalPath) {
		got = append(got, cp)
	})

	a.Feed(makeEvent(events.EventDBQuery, 1, 0, "")) // should be ignored
	a.Feed(makeEvent(events.EventHTTPResp, 1, 5_000_000, ""))

	if len(got) != 1 {
		t.Fatalf("expected 1 CriticalPath, got %d", len(got))
	}
	if len(got[0].Segments) != 1 {
		t.Errorf("zero-latency segment should be excluded, got %d segments", len(got[0].Segments))
	}
}

func TestEvict_FinalizesOldWindows(t *testing.T) {
	var got []criticalpath.CriticalPath
	a := criticalpath.New(1*time.Millisecond, func(cp criticalpath.CriticalPath) {
		got = append(got, cp)
	})

	a.Feed(makeEvent(events.EventDBQuery, 99, 1_000_000, ""))
	time.Sleep(5 * time.Millisecond)
	a.Evict()

	if len(got) != 1 {
		t.Fatalf("expected evicted window to be emitted, got %d", len(got))
	}
	if got[0].PID != 99 {
		t.Errorf("PID: want 99, got %d", got[0].PID)
	}
}

func TestFeed_NilEventSafe(t *testing.T) {
	a := criticalpath.New(0, func(_ criticalpath.CriticalPath) {})
	a.Feed(nil) // must not panic
}

func TestNew_ZeroTimeoutDefaulted(t *testing.T) {
	// Should not panic even with zero timeout.
	a := criticalpath.New(0, func(_ criticalpath.CriticalPath) {})
	if a == nil {
		t.Fatal("expected non-nil Analyzer")
	}
}
