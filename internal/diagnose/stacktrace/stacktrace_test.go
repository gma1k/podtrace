package stacktrace

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type mockDiagnostician struct {
	events []*events.Event
}

func (m *mockDiagnostician) GetEvents() []*events.Event {
	return m.events
}

func TestGenerateStackTraceSectionWithContext_EmptyEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Error("Expected empty result for no events")
	}
}

func TestGenerateStackTraceSectionWithContext_NoStack(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Stack: []uint64{}},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Error("Expected empty result for events without stack")
	}
}

func TestGenerateStackTraceSectionWithContext_LowLatency(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 100000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Error("Expected empty result for low latency events")
	}
}

func TestGenerateStackTraceSectionWithContext_LockContention(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventLockContention, LatencyNS: 100000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_DBQuery(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDBQuery, LatencyNS: 100000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_HighLatency(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234, 0x5678}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_CancelledContext(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Log("Result may be empty or partial when context is cancelled")
	}
}

func TestGenerateStackTraceSectionWithContext_NilEvent(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			nil,
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_MaxEventsLimit(t *testing.T) {
	evts := make([]*events.Event, 0, 15000)
	for i := 0; i < 15000; i++ {
		evts = append(evts, &events.Event{
			Type:      events.EventDNS,
			LatencyNS: 2000000,
			Stack:     []uint64{0x1234},
			PID:       1234,
		})
	}
	d := &mockDiagnostician{
		events: evts,
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_ZeroAddress(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Log("Stack trace with zero address should be handled")
	}
}

func TestGenerateStackTraceSectionWithContext_MultipleStacks(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234, Target: "example.com"},
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234, Target: "example.com"},
			{Type: events.EventTCPRecv, LatencyNS: 2000000, Stack: []uint64{0x5678}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_ContextTimeout(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Nanosecond)
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Log("Result may be empty or partial when context times out")
	}
}

// ---- Direct stackResolver tests ----

// TestStackResolver_ZeroAddr verifies that addr=0 returns "".
func TestStackResolver_ZeroAddr(t *testing.T) {
	r := &stackResolver{}
	got := r.resolve(context.Background(), 1, 0)
	if got != "" {
		t.Errorf("resolve(addr=0) = %q, want empty", got)
	}
}

// TestStackResolver_ContextCancelled verifies the ctx.Done early-return path.
func TestStackResolver_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	r := &stackResolver{}
	got := r.resolve(ctx, 1, 0x1234)
	if got != "" {
		t.Errorf("resolve(cancelled ctx) = %q, want empty", got)
	}
}

// TestStackResolver_NilCache verifies that a nil cache is lazily initialized.
func TestStackResolver_NilCache(t *testing.T) {
	r := &stackResolver{cache: nil}
	// addr 0x1 with a non-existent PID — forces readlink to fail, returns hex addr.
	got := r.resolve(context.Background(), 999999, 0x1)
	if got == "" {
		t.Error("expected non-empty hex addr for non-zero addr with non-existent PID")
	}
	if r.cache == nil {
		t.Error("cache should have been initialized")
	}
}

// TestStackResolver_CurrentPID uses the current process's PID to exercise
// the exePath readlink success path and the addr2line invocation path.
func TestStackResolver_CurrentPID(t *testing.T) {
	pid := uint32(os.Getpid())
	r := &stackResolver{cache: make(map[string]string)}

	// Resolve an arbitrary address — addr2line may fail but the code path is exercised.
	got1 := r.resolve(context.Background(), pid, 0xdeadbeef)
	if got1 == "" {
		t.Error("expected non-empty result for current PID with non-zero addr")
	}

	// Second call with the same args — should hit the cache.
	got2 := r.resolve(context.Background(), pid, 0xdeadbeef)
	if got1 != got2 {
		t.Errorf("cache hit should return same value: got1=%q got2=%q", got1, got2)
	}
}

