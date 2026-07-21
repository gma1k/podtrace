package tracker

import (
	"fmt"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func TestGetSummary_SortsByConnectionCount(t *testing.T) {
	pct := NewPodCommunicationTracker("src", "ns")
	ts := uint64(time.Now().UnixNano())
	quiet := map[string]interface{}{"target_pod": "quiet", "target_namespace": "ns"}
	busy := map[string]interface{}{"target_pod": "busy", "target_namespace": "ns"}

	pct.ProcessEvent(&events.Event{Type: events.EventConnect, Timestamp: ts}, quiet)
	for i := 0; i < 3; i++ {
		pct.ProcessEvent(&events.Event{Type: events.EventConnect, Timestamp: ts}, busy)
	}

	summaries := pct.GetSummary()
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}
	if summaries[0].Target != "busy" {
		t.Errorf("summaries must be sorted by connection count; first = %q, want busy", summaries[0].Target)
	}
}

func TestGeneratePoolCorrelation_LimitsPools(t *testing.T) {
	var evs []*events.Event
	ts := uint64(time.Now().UnixNano())
	for i := 0; i < config.MaxConnectionTargets+3; i++ {
		evs = append(evs, &events.Event{
			Type:      events.EventPoolAcquire,
			Target:    fmt.Sprintf("pool-%03d", i),
			Timestamp: ts,
		})
	}
	report := GeneratePoolCorrelation(evs)
	if report == "" {
		t.Fatal("expected a non-empty pool correlation report")
	}
	if got := countSubstr(report, "        Acquires:"); got != config.MaxConnectionTargets {
		t.Errorf("rendered %d pools, want the cap of %d", got, config.MaxConnectionTargets)
	}
}

func TestDeterminePoolHealth_ExhaustedNoAcquires(t *testing.T) {
	got := determinePoolHealthFromSummary(PoolSummary{ExhaustedCount: 1, AcquireCount: 0})
	if got != "CRITICAL - Pool exhausted with no successful acquisitions" {
		t.Errorf("health = %q, want the no-acquisitions critical status", got)
	}
}

func TestAnalyzeProcessActivity_NilEventSkipped(t *testing.T) {
	evs := []*events.Event{
		nil,
		{PID: 100, ProcessName: "app", Timestamp: 1},
	}
	got := AnalyzeProcessActivity(evs)
	if len(got) != 1 || got[0].Pid != 100 {
		t.Fatalf("nil events must be skipped; got %+v", got)
	}
}

func TestAnalyzeProcessActivity_TransientNameFallback(t *testing.T) {
	evs := []*events.Event{
		{PID: 200, ProcessName: "runc:[2:INIT]", Timestamp: 5},
	}
	got := AnalyzeProcessActivity(evs)
	if len(got) != 1 {
		t.Fatalf("expected 1 pid entry, got %d", len(got))
	}
	if got[0].Name != "runc:[2:INIT]" {
		t.Errorf("Name = %q, want the transient name when no stable name exists", got[0].Name)
	}
}

func TestAnalyzeProcessActivity_StableNamePreferredOverTransient(t *testing.T) {
	evs := []*events.Event{
		{PID: 300, ProcessName: "runc:[2:INIT]", Timestamp: 1},
		{PID: 300, ProcessName: "nginx", Timestamp: 2},
	}
	got := AnalyzeProcessActivity(evs)
	if len(got) != 1 || got[0].Name != "nginx" {
		t.Fatalf("stable name must win over transient; got %+v", got)
	}
}

func TestProcessEvent_CorrelationIDAttribute(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(&events.Event{
		Type:          events.EventHTTPReq,
		TraceID:       "t-corr",
		SpanID:        "s-corr",
		CorrelationID: 987654321,
	}, nil)

	trace := tt.GetTrace("t-corr")
	if trace == nil || len(trace.Spans) != 1 {
		t.Fatalf("expected one span in trace t-corr, got %+v", trace)
	}
	if got := trace.Spans[0].Attributes["podtrace.correlation_id"]; got != "987654321" {
		t.Errorf("correlation_id attribute = %q, want 987654321", got)
	}
}

func TestProcessEvent_NonMapContextIgnored(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "t-ctx",
		SpanID:  "s-ctx",
	}, "not-a-map")

	trace := tt.GetTrace("t-ctx")
	if trace == nil || len(trace.Spans) != 1 {
		t.Fatalf("expected one span in trace t-ctx, got %+v", trace)
	}
	if len(trace.Services) != 0 {
		t.Errorf("a non-map context must not populate services, got %+v", trace.Services)
	}
}

func TestCommitExport_UnknownTraceSkipped(t *testing.T) {
	tt := NewTraceTracker()
	tt.CommitExport([]*Trace{{TraceID: "does-not-exist", Spans: []*Span{{SpanID: "x"}}}})
	if tt.GetTraceCount() != 0 {
		t.Error("committing an unknown trace must not create state")
	}
}

func TestCommitExport_ClampsExportedSpans(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(&events.Event{Type: events.EventHTTPReq, TraceID: "t1", SpanID: "s1"}, nil)

	overClaim := &Trace{TraceID: "t1", Spans: []*Span{{SpanID: "a"}, {SpanID: "b"}, {SpanID: "c"}}}
	tt.CommitExport([]*Trace{overClaim})

	if got := tt.SnapshotForExport(time.Hour, true); len(got) != 0 {
		t.Errorf("watermark must clamp to the live span count; re-export = %d traces", len(got))
	}
}

func TestCloneTrace_CopiesServicesAndLabels(t *testing.T) {
	tt := NewTraceTracker()
	ctx := map[string]interface{}{
		"target_service":   "checkout",
		"target_namespace": "shop",
		"target_labels":    map[string]string{"app": "checkout", "tier": "web"},
	}
	tt.ProcessEvent(&events.Event{Type: events.EventHTTPReq, TraceID: "t1", SpanID: "s1"}, ctx)

	snaps := tt.SnapshotAll()
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snaps))
	}
	svc, ok := snaps[0].Services["shop/checkout"]
	if !ok {
		t.Fatalf("cloned trace missing service key shop/checkout: %+v", snaps[0].Services)
	}
	if svc.Labels["app"] != "checkout" || svc.Labels["tier"] != "web" {
		t.Errorf("cloned labels = %+v, want app=checkout tier=web", svc.Labels)
	}

	svc.Labels["app"] = "mutated"
	live := tt.GetTrace("t1")
	live.mu.RLock()
	defer live.mu.RUnlock()
	if live.Services["shop/checkout"].Labels["app"] != "checkout" {
		t.Error("mutating a cloned label leaked into the live trace (labels not deep-copied)")
	}
}

func countSubstr(s, sub string) int {
	count := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			count++
		}
	}
	return count
}
