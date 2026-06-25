package criticalpath_test

import (
	"strings"
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
	// The boundary response (10ms) spans the whole request, so it IS the
	// total; the DB and Redis segments are parts of it. The old behavior
	// summed the boundary on top of its parts (16ms "total" for a 10ms
	// request) — fractions were diluted by the double count.
	if len(cp.Segments) != 2 {
		t.Fatalf("expected 2 segments (boundary excluded), got %d", len(cp.Segments))
	}
	totalNS := uint64(cp.TotalLatency)
	if totalNS != 10_000_000 {
		t.Errorf("TotalLatency: want the boundary's 10ms, got %d ns", totalNS)
	}
	var sum float64
	for _, s := range cp.Segments {
		sum += s.Fraction
	}
	if sum < 0.599 || sum > 0.601 {
		t.Errorf("fractions: want 0.6 of the request attributed (5ms+1ms of 10ms), got %f", sum)
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

func TestCriticalPath_Breakdown_AggregatesAndDedupes(t *testing.T) {
	cp := criticalpath.CriticalPath{
		PID:          42,
		TotalLatency: 100,
		Segments: []criticalpath.Segment{
			{Label: "FS", Fraction: 0.0},
			{Label: "NET", Fraction: 0.5},
			{Label: "DNS", Fraction: 0.03},
			{Label: "NET", Fraction: 0.4}, // duplicate label → must aggregate
			{Label: "CPU", Fraction: 0.25},
			{Label: "FS", Fraction: 0.0},  // duplicate label
		},
	}
	got := cp.Breakdown(5)

	// No label may appear more than once (the original bug emitted duplicates).
	for _, label := range []string{"NET", "FS", "DNS", "CPU"} {
		if c := strings.Count(got, label+" "); c != 1 {
			t.Errorf("label %q appears %d times in %q, want exactly 1", label, c, got)
		}
	}
	// NET (0.5+0.4=0.9) must lead, ahead of CPU (0.25).
	if !strings.HasPrefix(got, "NET 90.0%") {
		t.Errorf("breakdown = %q, want it to lead with aggregated NET 90.0%%", got)
	}
	if strings.Index(got, "NET") > strings.Index(got, "CPU") {
		t.Errorf("breakdown = %q, want NET before CPU (descending)", got)
	}
}

func TestCriticalPath_Breakdown_TopNAndEmpty(t *testing.T) {
	if got := (criticalpath.CriticalPath{}).Breakdown(5); got != "" {
		t.Errorf("empty breakdown = %q, want \"\"", got)
	}
	cp := criticalpath.CriticalPath{Segments: []criticalpath.Segment{
		{Label: "A", Fraction: 0.5}, {Label: "B", Fraction: 0.4},
		{Label: "C", Fraction: 0.3}, {Label: "D", Fraction: 0.2},
	}}
	got := cp.Breakdown(2)
	if strings.Count(got, ",") != 1 {
		t.Errorf("topN=2 breakdown = %q, want exactly 2 entries", got)
	}
	if !strings.Contains(got, "A ") || !strings.Contains(got, "B ") || strings.Contains(got, "C ") {
		t.Errorf("topN=2 breakdown = %q, want only the top 2 (A,B)", got)
	}
}
