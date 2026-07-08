package tracker

import (
	"strconv"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type TraceTracker struct {
	mu     sync.RWMutex
	traces map[string]*Trace
}

type Trace struct {
	TraceID   string
	Spans     []*Span
	StartTime time.Time
	EndTime   time.Time
	Services  map[string]*ServiceInfo
	mu        sync.RWMutex

	exportedSpans int
	lastUpdate    time.Time
}

type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Service      string
	Operation    string
	StartTime    time.Time
	Duration     time.Duration
	Events       []*events.Event
	Attributes   map[string]string
	Error        bool
}

type ServiceInfo struct {
	Name      string
	Namespace string
	Pod       string
	Labels    map[string]string
}

func NewTraceTracker() *TraceTracker {
	return &TraceTracker{
		traces: make(map[string]*Trace),
	}
}

func (tt *TraceTracker) ProcessEvent(event *events.Event, k8sContext interface{}) {
	if event == nil {
		return
	}

	if event.TraceID == "" {
		return
	}

	tt.mu.Lock()
	trace, exists := tt.traces[event.TraceID]
	if !exists {
		trace = &Trace{
			TraceID:   event.TraceID,
			Spans:     make([]*Span, 0),
			StartTime: event.TimestampTime(),
			EndTime:   event.TimestampTime(),
			Services:  make(map[string]*ServiceInfo),
		}
		tt.traces[event.TraceID] = trace
	}
	tt.mu.Unlock()

	trace.mu.Lock()
	defer trace.mu.Unlock()

	trace.lastUpdate = time.Now()
	if event.TimestampTime().Before(trace.StartTime) {
		trace.StartTime = event.TimestampTime()
	}
	if event.TimestampTime().After(trace.EndTime) {
		trace.EndTime = event.TimestampTime()
	}

	span := tt.findOrCreateSpan(trace, event)
	if span == nil {
		return
	}

	span.Events = append(span.Events, event)
	span.UpdateDuration()
	if event.Error != 0 {
		span.Error = true
	}

	if k8sContext != nil {
		tt.updateServiceInfo(trace, span, k8sContext)
	}
}

func (tt *TraceTracker) findOrCreateSpan(trace *Trace, event *events.Event) *Span {
	for _, span := range trace.Spans {
		if span.SpanID == event.SpanID {
			return span
		}
	}

	span := &Span{
		TraceID:      event.TraceID,
		SpanID:       event.SpanID,
		ParentSpanID: event.ParentSpanID,
		StartTime:    event.TimestampTime(),
		Events:       make([]*events.Event, 0),
		Attributes:   make(map[string]string),
		Operation:    event.TypeString(),
	}

	if event.ProcessName != "" {
		span.Service = event.ProcessName
		span.Attributes["process.name"] = event.ProcessName
	}
	if event.PID > 0 {
		span.Attributes["process.pid"] = strconv.FormatUint(uint64(event.PID), 10)
	}
	if event.Target != "" {
		span.Attributes["target"] = event.Target
	}
	if event.Details != "" {
		span.Attributes["details"] = event.Details
	}
	if event.CorrelationID != 0 {
		span.Attributes["podtrace.correlation_id"] = strconv.FormatUint(event.CorrelationID, 10)
	}

	trace.Spans = append(trace.Spans, span)
	return span
}

func (tt *TraceTracker) updateServiceInfo(trace *Trace, span *Span, k8sContext interface{}) {
	ctx, ok := k8sContext.(map[string]interface{})
	if !ok {
		return
	}

	var serviceName, namespace, podName string
	var labels map[string]string

	if svc, ok := ctx["target_service"].(string); ok && svc != "" {
		serviceName = svc
	}
	if ns, ok := ctx["target_namespace"].(string); ok && ns != "" {
		namespace = ns
	}
	if pod, ok := ctx["target_pod"].(string); ok && pod != "" {
		podName = pod
	}
	if lbls, ok := ctx["target_labels"].(map[string]string); ok {
		labels = lbls
	}

	if serviceName == "" && podName == "" {
		return
	}

	key := serviceName
	if key == "" {
		key = podName
	}
	if namespace != "" {
		key = namespace + "/" + key
	}

	if _, exists := trace.Services[key]; !exists {
		trace.Services[key] = &ServiceInfo{
			Name:      serviceName,
			Namespace: namespace,
			Pod:       podName,
			Labels:    labels,
		}
	}

	if serviceName != "" {
		span.Service = serviceName
		span.Attributes["service.name"] = serviceName
	}
	if namespace != "" {
		span.Attributes["service.namespace"] = namespace
	}
	if podName != "" {
		span.Attributes["pod.name"] = podName
	}
}

func (tt *TraceTracker) GetTrace(traceID string) *Trace {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	return tt.traces[traceID]
}

func (tt *TraceTracker) GetAllTraces() []*Trace {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	traces := make([]*Trace, 0, len(tt.traces))
	for _, trace := range tt.traces {
		traces = append(traces, trace)
	}
	return traces
}

// SnapshotForExport returns deep copies of traces carrying only the spans
// that have not been handed to an exporter yet, and advances each trace's
// watermark.
func (tt *TraceTracker) SnapshotForExport(settle time.Duration, force bool) []*Trace {
	tt.mu.RLock()
	live := make([]*Trace, 0, len(tt.traces))
	for _, trace := range tt.traces {
		live = append(live, trace)
	}
	tt.mu.RUnlock()

	now := time.Now()
	out := make([]*Trace, 0, len(live))
	for _, trace := range live {
		trace.mu.Lock()
		if !force && now.Sub(trace.lastUpdate) < settle {
			trace.mu.Unlock()
			continue
		}
		if trace.exportedSpans >= len(trace.Spans) {
			trace.mu.Unlock()
			continue
		}
		snapshot := cloneTraceLocked(trace, trace.exportedSpans)
		trace.exportedSpans = len(trace.Spans)
		trace.mu.Unlock()
		out = append(out, snapshot)
	}
	return out
}

// SnapshotAll returns deep copies of every trace (all spans) without touching
// export watermarks — for read-only consumers like the request-flow graph.
func (tt *TraceTracker) SnapshotAll() []*Trace {
	tt.mu.RLock()
	live := make([]*Trace, 0, len(tt.traces))
	for _, trace := range tt.traces {
		live = append(live, trace)
	}
	tt.mu.RUnlock()

	out := make([]*Trace, 0, len(live))
	for _, trace := range live {
		trace.mu.RLock()
		out = append(out, cloneTraceLocked(trace, 0))
		trace.mu.RUnlock()
	}
	return out
}

// cloneTraceLocked deep-copies a trace, including only spans from index
// fromSpan on. Caller must hold trace.mu. Event pointers are shared — events
// are not mutated after ProcessEvent — but every slice and map is copied.
func cloneTraceLocked(trace *Trace, fromSpan int) *Trace {
	out := &Trace{
		TraceID:   trace.TraceID,
		StartTime: trace.StartTime,
		EndTime:   trace.EndTime,
		Services:  make(map[string]*ServiceInfo, len(trace.Services)),
		Spans:     make([]*Span, 0, len(trace.Spans)-fromSpan),
	}
	for k, v := range trace.Services {
		info := *v
		if v.Labels != nil {
			info.Labels = make(map[string]string, len(v.Labels))
			for lk, lv := range v.Labels {
				info.Labels[lk] = lv
			}
		}
		out.Services[k] = &info
	}
	for _, span := range trace.Spans[fromSpan:] {
		s := &Span{
			TraceID:      span.TraceID,
			SpanID:       span.SpanID,
			ParentSpanID: span.ParentSpanID,
			Service:      span.Service,
			Operation:    span.Operation,
			StartTime:    span.StartTime,
			Duration:     span.Duration,
			Error:        span.Error,
			Events:       make([]*events.Event, len(span.Events)),
			Attributes:   make(map[string]string, len(span.Attributes)),
		}
		copy(s.Events, span.Events)
		for ak, av := range span.Attributes {
			s.Attributes[ak] = av
		}
		out.Spans = append(out.Spans, s)
	}
	return out
}

func (tt *TraceTracker) CleanupOldTraces(maxAge time.Duration) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	now := time.Now()
	for traceID, trace := range tt.traces {
		trace.mu.RLock()
		age := now.Sub(trace.EndTime)
		trace.mu.RUnlock()
		if age > maxAge {
			delete(tt.traces, traceID)
		}
	}
}

func (tt *TraceTracker) GetTraceCount() int {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	return len(tt.traces)
}

// UpdateDuration recomputes the span's start and duration from its events.
func (s *Span) UpdateDuration() {
	if len(s.Events) == 0 {
		return
	}

	first := s.Events[0]
	start := first.TimestampTime().Add(-first.Latency())
	end := first.TimestampTime()

	for _, event := range s.Events {
		hi := event.TimestampTime()
		lo := hi.Add(-event.Latency())
		if lo.Before(start) {
			start = lo
		}
		if hi.After(end) {
			end = hi
		}
	}

	s.StartTime = start
	s.Duration = end.Sub(start)
}
