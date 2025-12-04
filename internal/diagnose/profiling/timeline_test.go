package profiling

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestAnalyzeTimeline_Basic(t *testing.T) {
	start := time.Now()
	duration := 5 * time.Second

	var evs []*events.Event
	for i := 0; i < 10; i++ {
		evs = append(evs, &events.Event{
			Timestamp: uint64(start.Add(time.Duration(i) * time.Second).UnixNano()),
		})
	}

	buckets := AnalyzeTimeline(evs, start, duration)
	if len(buckets) != 5 {
		t.Fatalf("expected 5 buckets, got %d", len(buckets))
	}
}

func TestDetectBursts(t *testing.T) {
	start := time.Now()
	duration := 2 * time.Second

	var evs []*events.Event
	for i := 0; i < 20; i++ {
		evs = append(evs, &events.Event{
			Timestamp: uint64(start.Add(500 * time.Millisecond).UnixNano()),
		})
	}

	_ = DetectBursts(evs, start, duration)
}

func TestAnalyzeConnectionPattern_Empty(t *testing.T) {
	cp := AnalyzeConnectionPattern(nil, time.Now(), time.Now(), time.Second)
	if cp.Pattern != "" {
		t.Fatalf("expected empty pattern for no events, got %q", cp.Pattern)
	}
}

func TestAnalyzeConnectionPattern_Basic(t *testing.T) {
	start := time.Now()
	end := start.Add(10 * time.Second)
	duration := end.Sub(start)

	evs := []*events.Event{
		{Timestamp: uint64(start.Add(time.Second).UnixNano()), Target: "example.com"},
		{Timestamp: uint64(start.Add(2 * time.Second).UnixNano()), Target: "api.example.com"},
	}

	cp := AnalyzeConnectionPattern(evs, start, end, duration)
	if cp.AvgRate <= 0 {
		t.Fatalf("expected positive avg rate")
	}
}

func TestAnalyzeIOPattern_Basic(t *testing.T) {
	start := time.Now()
	duration := 5 * time.Second
	evs := []*events.Event{
		{Type: events.EventTCPSend, Timestamp: uint64(start.Add(time.Second).UnixNano())},
		{Type: events.EventTCPRecv, Timestamp: uint64(start.Add(2 * time.Second).UnixNano())},
	}

	p := AnalyzeIOPattern(evs, start, duration)
	if p.AvgThroughput <= 0 {
		t.Fatalf("expected positive avg throughput")
	}
}
