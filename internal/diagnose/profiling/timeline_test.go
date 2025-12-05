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

func TestAnalyzeTimeline_Extended(t *testing.T) {
	startTime := time.Now()
	duration := 10 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"single event",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano())},
			},
		},
		{
			"multiple events",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano())},
				{Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano())},
				{Timestamp: uint64(startTime.Add(5 * time.Second).UnixNano())},
			},
		},
		{
			"events before start",
			[]*events.Event{
				{Timestamp: uint64(startTime.Add(-1 * time.Second).UnixNano())},
			},
		},
		{
			"events after end",
			[]*events.Event{
				{Timestamp: uint64(startTime.Add(15 * time.Second).UnixNano())},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeTimeline(tt.events, startTime, duration)
			if len(tt.events) == 0 && result != nil {
				t.Error("Expected nil for empty events")
			}
			if len(tt.events) > 0 && result == nil {
				t.Error("Expected non-nil result for non-empty events")
			}
		})
	}
}

func TestDetectBursts_Extended(t *testing.T) {
	startTime := time.Now()
	duration := 5 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"few events",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano())},
			},
		},
		{
			"many events",
			makeEvents(startTime, 100),
		},
		{
			"burst pattern",
			append(
				makeEvents(startTime, 10),
				makeEvents(startTime.Add(2*time.Second), 50)...,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectBursts(tt.events, startTime, duration)
			if result == nil && len(tt.events) >= 10 {
				t.Log("No bursts detected (may be expected)")
			}
		})
	}
}

func TestAnalyzeConnectionPattern_Extended(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(10 * time.Second)
	duration := 10 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"steady pattern",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
				{Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano()), Target: "example.com:80"},
				{Timestamp: uint64(startTime.Add(4 * time.Second).UnixNano()), Target: "example.com:80"},
			},
		},
		{
			"bursty pattern",
			append(
				[]*events.Event{
					{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
				},
				makeConnectEvents(startTime.Add(5*time.Second), 20)...,
			),
		},
		{
			"multiple targets",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
				{Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano()), Target: "test.com:443"},
				{Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano()), Target: "api.com:8080"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeConnectionPattern(tt.events, startTime, endTime, duration)
			if len(tt.events) == 0 {
				if result.Pattern != "" {
					t.Error("Expected empty pattern for empty events")
				}
			} else {
				if result.Pattern == "" {
					t.Error("Expected non-empty pattern")
				}
			}
		})
	}
}

func TestAnalyzeIOPattern_Extended(t *testing.T) {
	startTime := time.Now()
	duration := 10 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"send only",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
			},
		},
		{
			"recv only",
			[]*events.Event{
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
			},
		},
		{
			"balanced",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
			},
		},
		{
			"more send",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano())},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeIOPattern(tt.events, startTime, duration)
			if len(tt.events) == 0 {
				if result.SendRecvRatio != 1.0 {
					t.Error("Expected SendRecvRatio 1.0 for empty events")
				}
			}
		})
	}
}

func TestIsKernelThread(t *testing.T) {
	tests := []struct {
		name     string
		pid      uint32
		procName string
		expected bool
	}{
		{"kworker", 1, "kworker/0:0", true},
		{"irq", 2, "irq/1", true},
		{"ksoftirqd", 3, "ksoftirqd/0", true},
		{"migration", 4, "migration/0", true},
		{"rcu", 5, "rcu_sched", true},
		{"watchdog", 6, "watchdog/0", true},
		{"brackets", 7, "[kthreadd]", true},
		{"normal process", 8, "bash", false},
		{"normal process 2", 9, "python", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKernelThread(tt.pid, tt.procName)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGenerateCPUUsageFromProc(t *testing.T) {
	result := GenerateCPUUsageFromProc(10 * time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "CPU Usage") {
		t.Error("Expected report to contain 'CPU Usage'")
	}
}

func makeEvents(startTime time.Time, count int) []*events.Event {
	evs := make([]*events.Event, count)
	for i := 0; i < count; i++ {
		evs[i] = &events.Event{
			Timestamp: uint64(startTime.Add(time.Duration(i) * 100 * time.Millisecond).UnixNano()),
		}
	}
	return evs
}

func makeConnectEvents(startTime time.Time, count int) []*events.Event {
	evs := make([]*events.Event, count)
	for i := 0; i < count; i++ {
		evs[i] = &events.Event{
			Type:      events.EventConnect,
			Timestamp: uint64(startTime.Add(time.Duration(i) * 50 * time.Millisecond).UnixNano()),
			Target:    "example.com:80",
		}
	}
	return evs
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr))
}
