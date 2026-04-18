package tracker

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestNewTraceTracker(t *testing.T) {
	tt := NewTraceTracker()
	if tt == nil {
		t.Fatal("NewTraceTracker returned nil")
	}
	if tt.GetTraceCount() != 0 {
		t.Error("New tracker should have 0 traces")
	}
}

func TestTraceTracker_ProcessEvent(t *testing.T) {
	tt := NewTraceTracker()

	event := &events.Event{
		TraceID:      "trace123",
		SpanID:       "span123",
		ParentSpanID: "",
		Type:         events.EventHTTPReq,
		Timestamp:    uint64(time.Now().UnixNano()),
		ProcessName:  "test-process",
		Target:       "http://example.com",
	}

	tt.ProcessEvent(event, nil)

	if tt.GetTraceCount() != 1 {
		t.Errorf("Expected 1 trace, got %d", tt.GetTraceCount())
	}

	trace := tt.GetTrace("trace123")
	if trace == nil {
		t.Fatal("Trace not found")
	}
	if len(trace.Spans) != 1 {
		t.Errorf("Expected 1 span, got %d", len(trace.Spans))
	}
}

func TestTraceTracker_ProcessEvent_WithK8sContext(t *testing.T) {
	tt := NewTraceTracker()

	event := &events.Event{
		TraceID:     "trace123",
		SpanID:      "span123",
		Type:        events.EventHTTPReq,
		Timestamp:   uint64(time.Now().UnixNano()),
		ProcessName: "test-process",
	}

	k8sCtx := map[string]interface{}{
		"target_service":   "test-service",
		"target_namespace": "default",
		"target_pod":       "test-pod",
		"target_labels":    map[string]string{"app": "test"},
	}

	tt.ProcessEvent(event, k8sCtx)

	trace := tt.GetTrace("trace123")
	if trace == nil {
		t.Fatal("Trace not found")
	}

	if len(trace.Services) == 0 {
		t.Error("Services should be populated")
	}
}

func TestTraceTracker_ProcessEvent_NoTraceID(t *testing.T) {
	tt := NewTraceTracker()

	event := &events.Event{
		TraceID: "",
		SpanID:  "span123",
		Type:    events.EventHTTPReq,
	}

	tt.ProcessEvent(event, nil)

	if tt.GetTraceCount() != 0 {
		t.Error("Event without TraceID should not create trace")
	}
}

func TestTraceTracker_GetAllTraces(t *testing.T) {
	tt := NewTraceTracker()

	event1 := &events.Event{
		TraceID:   "trace1",
		SpanID:    "span1",
		Timestamp: uint64(time.Now().UnixNano()),
		Type:      events.EventHTTPReq,
	}

	event2 := &events.Event{
		TraceID:   "trace2",
		SpanID:    "span2",
		Timestamp: uint64(time.Now().UnixNano()),
		Type:      events.EventHTTPReq,
	}

	tt.ProcessEvent(event1, nil)
	tt.ProcessEvent(event2, nil)

	traces := tt.GetAllTraces()
	if len(traces) != 2 {
		t.Errorf("Expected 2 traces, got %d", len(traces))
	}
}

func TestTraceTracker_CleanupOldTraces(t *testing.T) {
	tt := NewTraceTracker()

	oldTime := time.Now().Add(-15 * time.Minute)
	event := &events.Event{
		TraceID:   "old-trace",
		SpanID:    "span1",
		Timestamp: uint64(oldTime.UnixNano()),
		Type:      events.EventHTTPReq,
	}

	tt.ProcessEvent(event, nil)

	tt.CleanupOldTraces(10 * time.Minute)

	if tt.GetTraceCount() != 0 {
		t.Error("Old traces should be cleaned up")
	}
}

func TestSpan_UpdateDuration(t *testing.T) {
	span := &Span{
		TraceID:   "trace1",
		SpanID:    "span1",
		StartTime: time.Now(),
		Events: []*events.Event{
			{
				Timestamp: uint64(time.Now().UnixNano()),
				Type:      events.EventHTTPReq,
			},
			{
				Timestamp: uint64(time.Now().Add(100 * time.Millisecond).UnixNano()),
				Type:      events.EventHTTPResp,
			},
		},
	}

	span.UpdateDuration()

	if span.Duration == 0 {
		t.Error("Duration should be updated")
	}
}

// ─── TraceTracker edge cases ─────────────────────────────────────────────────

// TestTraceTracker_ProcessEvent_Nil covers the nil-event early return.
func TestTraceTracker_ProcessEvent_Nil(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(nil, nil) // should not panic
	if tt.GetTraceCount() != 0 {
		t.Error("nil event should not create a trace")
	}
}

// TestTraceTracker_ProcessEvent_ErrorEvent covers span.Error = true path.
func TestTraceTracker_ProcessEvent_ErrorEvent(t *testing.T) {
	tt := NewTraceTracker()
	event := &events.Event{
		TraceID:   "trace-err",
		SpanID:    "span-err",
		Type:      events.EventConnect,
		Timestamp: uint64(time.Now().UnixNano()),
		Error:     1,
	}
	tt.ProcessEvent(event, nil)
	trace := tt.GetTrace("trace-err")
	if trace == nil || len(trace.Spans) == 0 {
		t.Fatal("expected trace with one span")
	}
	if !trace.Spans[0].Error {
		t.Error("expected span.Error = true for error event")
	}
}

// TestTraceTracker_ProcessEvent_EarlierTimestamp covers the StartTime update path.
func TestTraceTracker_ProcessEvent_EarlierTimestamp(t *testing.T) {
	tt := NewTraceTracker()
	baseTime := time.Now()

	// First event sets the trace start/end.
	ev1 := &events.Event{
		TraceID:   "t1",
		SpanID:    "s1",
		Type:      events.EventHTTPReq,
		Timestamp: uint64(baseTime.UnixNano()),
	}
	tt.ProcessEvent(ev1, nil)

	// Second event has an earlier timestamp → triggers StartTime update.
	ev2 := &events.Event{
		TraceID:   "t1",
		SpanID:    "s2",
		Type:      events.EventHTTPResp,
		Timestamp: uint64(baseTime.Add(-100 * time.Millisecond).UnixNano()),
	}
	tt.ProcessEvent(ev2, nil)

	trace := tt.GetTrace("t1")
	if trace == nil {
		t.Fatal("expected trace to exist")
	}
	if !trace.StartTime.Before(baseTime) {
		t.Errorf("expected StartTime before base %v, got %v", baseTime, trace.StartTime)
	}
}

// TestTraceTracker_ProcessEvent_LaterTimestamp covers the EndTime update path.
func TestTraceTracker_ProcessEvent_LaterTimestamp(t *testing.T) {
	tt := NewTraceTracker()
	baseTime := time.Now()

	ev1 := &events.Event{
		TraceID:   "t2",
		SpanID:    "s1",
		Type:      events.EventHTTPReq,
		Timestamp: uint64(baseTime.UnixNano()),
	}
	tt.ProcessEvent(ev1, nil)

	// Second event has a later timestamp → triggers EndTime update.
	ev2 := &events.Event{
		TraceID:   "t2",
		SpanID:    "s2",
		Type:      events.EventHTTPResp,
		Timestamp: uint64(baseTime.Add(200 * time.Millisecond).UnixNano()),
	}
	tt.ProcessEvent(ev2, nil)

	trace := tt.GetTrace("t2")
	if trace == nil {
		t.Fatal("expected trace to exist")
	}
	if !trace.EndTime.After(baseTime) {
		t.Errorf("expected EndTime after base %v, got %v", baseTime, trace.EndTime)
	}
}

// TestTraceTracker_ProcessEvent_ExistingSpan covers the findOrCreateSpan path
// where the span already exists (same SpanID used twice).
func TestTraceTracker_ProcessEvent_ExistingSpan(t *testing.T) {
	tt := NewTraceTracker()
	ts := uint64(time.Now().UnixNano())
	const spanID = "same-span"

	ev1 := &events.Event{TraceID: "t3", SpanID: spanID, Type: events.EventHTTPReq, Timestamp: ts}
	ev2 := &events.Event{TraceID: "t3", SpanID: spanID, Type: events.EventHTTPResp, Timestamp: ts + 1000}
	tt.ProcessEvent(ev1, nil)
	tt.ProcessEvent(ev2, nil)

	trace := tt.GetTrace("t3")
	if trace == nil {
		t.Fatal("expected trace to exist")
	}
	if len(trace.Spans) != 1 {
		t.Errorf("expected 1 span (same SpanID reused), got %d", len(trace.Spans))
	}
	if len(trace.Spans[0].Events) != 2 {
		t.Errorf("expected 2 events in span, got %d", len(trace.Spans[0].Events))
	}
}

// TestTraceTracker_ProcessEvent_WithPIDAndDetails covers the PID and Details
// attribute paths in findOrCreateSpan.
func TestTraceTracker_ProcessEvent_WithPIDAndDetails(t *testing.T) {
	tt := NewTraceTracker()
	ev := &events.Event{
		TraceID:   "t4",
		SpanID:    "s4",
		Type:      events.EventHTTPReq,
		Timestamp: uint64(time.Now().UnixNano()),
		PID:       1234,
		Details:   "some detail",
	}
	tt.ProcessEvent(ev, nil)

	trace := tt.GetTrace("t4")
	if trace == nil || len(trace.Spans) == 0 {
		t.Fatal("expected trace with one span")
	}
	span := trace.Spans[0]
	if span.Attributes["details"] != "some detail" {
		t.Errorf("expected details attribute, got %q", span.Attributes["details"])
	}
	if span.Attributes["process.pid"] == "" {
		t.Error("expected process.pid attribute for PID>0")
	}
}

// TestTraceTracker_UpdateServiceInfo_NoPodNoService covers the early return
// in updateServiceInfo when both serviceName and podName are empty.
func TestTraceTracker_UpdateServiceInfo_NoPodNoService(t *testing.T) {
	tt := NewTraceTracker()
	ev := &events.Event{
		TraceID:   "t5",
		SpanID:    "s5",
		Type:      events.EventHTTPReq,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	k8sCtx := map[string]interface{}{
		"target_namespace": "default",
		// no target_pod, no target_service
	}
	tt.ProcessEvent(ev, k8sCtx)

	trace := tt.GetTrace("t5")
	if trace == nil {
		t.Fatal("expected trace")
	}
	if len(trace.Services) != 0 {
		t.Errorf("expected no services when pod and service are empty, got %d", len(trace.Services))
	}
}

// TestTraceTracker_UpdateServiceInfo_PodOnlyKey covers the path where
// serviceName is empty so podName becomes the key (line 160).
func TestTraceTracker_UpdateServiceInfo_PodOnlyKey(t *testing.T) {
	tt := NewTraceTracker()
	ev := &events.Event{
		TraceID:   "t6",
		SpanID:    "s6",
		Type:      events.EventHTTPReq,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	k8sCtx := map[string]interface{}{
		"target_pod":       "mypod",
		"target_namespace": "ns1",
		// no target_service
	}
	tt.ProcessEvent(ev, k8sCtx)

	trace := tt.GetTrace("t6")
	if trace == nil {
		t.Fatal("expected trace")
	}
	if len(trace.Services) == 0 {
		t.Error("expected service entry for pod-only context")
	}
}

// TestSpan_UpdateDuration_Empty covers the len(Events)==0 early return.
func TestSpan_UpdateDuration_Empty(t *testing.T) {
	span := &Span{
		TraceID:   "t",
		SpanID:    "s",
		StartTime: time.Now(),
		Events:    []*events.Event{},
	}
	span.UpdateDuration() // should not panic, Duration stays 0
	if span.Duration != 0 {
		t.Errorf("expected Duration=0 for empty events, got %v", span.Duration)
	}
}

// TestSpan_UpdateDuration_EarlierEvent covers the eventTime.Before(start) branch.
func TestSpan_UpdateDuration_EarlierEvent(t *testing.T) {
	now := time.Now()
	span := &Span{
		TraceID:   "t",
		SpanID:    "s",
		StartTime: now,
		Events: []*events.Event{
			{Timestamp: uint64(now.UnixNano()), Type: events.EventHTTPResp},
			{Timestamp: uint64(now.Add(-50 * time.Millisecond).UnixNano()), Type: events.EventHTTPReq},
		},
	}
	span.UpdateDuration()
	if span.Duration <= 0 {
		t.Errorf("expected positive duration, got %v", span.Duration)
	}
}

// ─── PodCommunicationTracker edge cases ──────────────────────────────────────

// TestPodCommunicationTracker_ProcessEvent_Nil covers the nil-event early return.
func TestPodCommunicationTracker_ProcessEvent_Nil(t *testing.T) {
	pct := NewPodCommunicationTracker("source", "ns")
	pct.ProcessEvent(nil, nil) // should not panic
	if len(pct.GetSummary()) != 0 {
		t.Error("nil event should not add communication")
	}
}

// TestPodCommunicationTracker_ProcessEvent_WithBytes covers comm.TotalBytes update.
func TestPodCommunicationTracker_ProcessEvent_WithBytes(t *testing.T) {
	pct := NewPodCommunicationTracker("source", "default")
	ev := &events.Event{
		Type:      events.EventTCPSend,
		Timestamp: uint64(time.Now().UnixNano()),
		Bytes:     1024,
	}
	k8sCtx := map[string]interface{}{
		"target_service":   "svc",
		"target_namespace": "default",
	}
	pct.ProcessEvent(ev, k8sCtx)
	summaries := pct.GetSummary()
	if len(summaries) == 0 {
		t.Fatal("expected summary")
	}
	if summaries[0].TotalBytes != 1024 {
		t.Errorf("expected TotalBytes=1024, got %d", summaries[0].TotalBytes)
	}
}

// TestPodCommunicationTracker_ProcessEvent_WithLatency covers comm.TotalLatency update.
func TestPodCommunicationTracker_ProcessEvent_WithLatency(t *testing.T) {
	pct := NewPodCommunicationTracker("source", "default")
	ev := &events.Event{
		Type:      events.EventTCPRecv,
		Timestamp: uint64(time.Now().UnixNano()),
		LatencyNS: 5000000, // 5ms
	}
	k8sCtx := map[string]interface{}{
		"target_service":   "svc2",
		"target_namespace": "default",
	}
	pct.ProcessEvent(ev, k8sCtx)
	summaries := pct.GetSummary()
	if len(summaries) == 0 {
		t.Fatal("expected summary")
	}
	if summaries[0].AvgLatency == 0 {
		t.Error("expected non-zero avg latency")
	}
}

// TestPodCommunicationTracker_ProcessEvent_WithError covers comm.ErrorCount update.
func TestPodCommunicationTracker_ProcessEvent_WithError(t *testing.T) {
	pct := NewPodCommunicationTracker("source", "default")
	ev := &events.Event{
		Type:      events.EventConnect,
		Timestamp: uint64(time.Now().UnixNano()),
		Error:     1,
	}
	k8sCtx := map[string]interface{}{
		"target_pod":       "target-pod",
		"target_namespace": "default",
	}
	pct.ProcessEvent(ev, k8sCtx)
	summaries := pct.GetSummary()
	if len(summaries) == 0 {
		t.Fatal("expected summary")
	}
	if summaries[0].ErrorCount != 1 {
		t.Errorf("expected ErrorCount=1, got %d", summaries[0].ErrorCount)
	}
}

// TestPodCommunicationTracker_GetSummary_PodTarget covers the target=TargetPod branch.
func TestPodCommunicationTracker_GetSummary_PodTarget(t *testing.T) {
	pct := NewPodCommunicationTracker("source", "default")
	ev := &events.Event{
		Type:      events.EventConnect,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	k8sCtx := map[string]interface{}{
		"target_pod":       "pod-only",
		"target_namespace": "default",
		// no target_service
	}
	pct.ProcessEvent(ev, k8sCtx)
	summaries := pct.GetSummary()
	if len(summaries) == 0 {
		t.Fatal("expected summary")
	}
	if summaries[0].Target != "pod-only" {
		t.Errorf("expected Target=pod-only, got %q", summaries[0].Target)
	}
}

// TestGeneratePodCommunicationReport_Empty covers the empty-summaries path.
func TestGeneratePodCommunicationReport_Empty(t *testing.T) {
	report := GeneratePodCommunicationReport(nil)
	if report != "" {
		t.Errorf("expected empty report for nil summaries, got %q", report)
	}
}

// TestGeneratePodCommunicationReport_WithErrors covers the ErrorCount > 0 formatting.
func TestGeneratePodCommunicationReport_WithErrors(t *testing.T) {
	summaries := []PodCommunicationSummary{
		{
			Target:          "svc",
			Namespace:       "ns",
			ConnectionCount: 5,
			TotalBytes:      2048,
			AvgLatency:      2 * time.Millisecond,
			ErrorCount:      3,
			LastSeen:        time.Now(),
		},
	}
	report := GeneratePodCommunicationReport(summaries)
	if report == "" {
		t.Fatal("expected non-empty report")
	}
}

// ─── Pool report coverage ─────────────────────────────────────────────────────

// TestGeneratePoolCorrelation_Empty covers the empty events path in
// GeneratePoolCorrelation (len(summaries) == 0 → return "").
func TestGeneratePoolCorrelation_Empty(t *testing.T) {
	report := GeneratePoolCorrelation(nil)
	if report != "" {
		t.Errorf("expected empty report for nil events, got %q", report)
	}
}

// TestGeneratePoolCorrelation_ManyPools covers report generation with pool events.
func TestGeneratePoolCorrelation_ManyPools(t *testing.T) {
	var evts []*events.Event
	// Create many pool acquire events with different pool IDs.
	for i := 0; i < 20; i++ {
		evts = append(evts, &events.Event{
			Type:      events.EventPoolAcquire,
			Target:    "pool",
			Timestamp: uint64(time.Now().UnixNano()),
		})
	}
	report := GeneratePoolCorrelation(evts)
	_ = report // just verify it doesn't panic
}

// ─── Process tracker coverage ────────────────────────────────────────────────

// TestAnalyzeProcessActivity_UnknownPID covers the getProcessName fallback when
// name is empty (line 41: name = "unknown").
func TestAnalyzeProcessActivity_UnknownPID(t *testing.T) {
	evts := []*events.Event{
		{
			Type:        events.EventExec,
			PID:         999999999, // non-existent PID
			Timestamp:   uint64(time.Now().UnixNano()),
			ProcessName: "", // no process name
		},
	}
	results := AnalyzeProcessActivity(evts)
	_ = results // just verify it doesn't panic
}
