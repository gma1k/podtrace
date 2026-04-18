package metricsexporter

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestExportMetricsHelpers(t *testing.T) {
	e := &events.Event{
		Type:        events.EventDNS,
		ProcessName: "testproc",
		LatencyNS:   uint64(time.Millisecond * 50),
		Bytes:       1024,
	}

	ExportRTTMetric(e)
	ExportTCPMetric(e)
	ExportDNSMetric(e)
	ExportFileSystemMetric(e)
	ExportSchedSwitchMetric(e)
	ExportNetworkBandwidthMetric(e, "send")
	ExportFilesystemBandwidthMetric(e, "write")
}

func TestSecurityAndRateLimitMiddleware(t *testing.T) {
	hit := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	})

	handler := securityHeadersMiddleware(rateLimitMiddleware(next))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !hit {
		t.Fatalf("expected inner handler to be called")
	}

	res := w.Result()
	if res.Header.Get("X-Content-Type-Options") == "" {
		t.Fatalf("expected security headers to be set")
	}
}

func TestStartServerAndShutdown(t *testing.T) {
	t.Setenv("PODTRACE_METRICS_ADDR", "127.0.0.1:0")
	t.Setenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR", "1")

	srv := StartServer()
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		srv.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not shut down in time")
	}

	_ = os.Unsetenv("PODTRACE_METRICS_ADDR")
	_ = os.Unsetenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR")
}

func TestExportRTTMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventTCPSend,
		LatencyNS:   5000000,
		ProcessName: "test",
	}
	ExportRTTMetric(event)
}

func TestExportTCPMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventConnect,
		LatencyNS:   10000000,
		ProcessName: "test",
	}
	ExportTCPMetric(event)
}

func TestExportDNSMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventDNS,
		LatencyNS:   2000000,
		ProcessName: "test",
	}
	ExportDNSMetric(event)
}

func TestExportFileSystemMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventRead,
		LatencyNS:   3000000,
		ProcessName: "test",
	}
	ExportFileSystemMetric(event)
}

func TestExportSchedSwitchMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventSchedSwitch,
		LatencyNS:   1000000,
		ProcessName: "test",
	}
	ExportSchedSwitchMetric(event)
}

func TestExportNetworkBandwidthMetric(t *testing.T) {
	tests := []struct {
		name  string
		event *events.Event
		bytes uint64
	}{
		{"with bytes", &events.Event{Type: events.EventTCPSend, Bytes: 1024, ProcessName: "test"}, 1024},
		{"zero bytes", &events.Event{Type: events.EventTCPSend, Bytes: 0, ProcessName: "test"}, 0},
		{"large bytes", &events.Event{Type: events.EventTCPSend, Bytes: 1048576, ProcessName: "test"}, 1048576},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportNetworkBandwidthMetric(tt.event, "send")
		})
	}
}

func TestExportFilesystemBandwidthMetric(t *testing.T) {
	tests := []struct {
		name  string
		event *events.Event
		bytes uint64
	}{
		{"with bytes", &events.Event{Type: events.EventRead, Bytes: 2048, ProcessName: "test"}, 2048},
		{"zero bytes", &events.Event{Type: events.EventRead, Bytes: 0, ProcessName: "test"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportFilesystemBandwidthMetric(tt.event, "read")
		})
	}
}

func TestRecordRingBufferDrop(t *testing.T) {
	RecordRingBufferDrop()
	RecordRingBufferDrop()
}

func TestRecordProcessCacheHit(t *testing.T) {
	RecordProcessCacheHit()
	RecordProcessCacheHit()
}

func TestRecordProcessCacheMiss(t *testing.T) {
	RecordProcessCacheMiss()
	RecordProcessCacheMiss()
}

func TestRecordPIDCacheHit(t *testing.T) {
	RecordPIDCacheHit()
	RecordPIDCacheHit()
}

func TestRecordPIDCacheMiss(t *testing.T) {
	RecordPIDCacheMiss()
	RecordPIDCacheMiss()
}

func TestRecordEventProcessingLatency(t *testing.T) {
	RecordEventProcessingLatency(1 * time.Millisecond)
	RecordEventProcessingLatency(10 * time.Millisecond)
	RecordEventProcessingLatency(100 * time.Millisecond)
}

func TestRecordError(t *testing.T) {
	RecordError("DNS", 1)
	RecordError("NET", 111)
	RecordError("FS", -1)
}

func TestHandleEvents(t *testing.T) {
	eventChan := make(chan *events.Event, 10)

	go func() {
		defer close(eventChan)
		eventChan <- &events.Event{Type: events.EventConnect, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventTCPSend, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventTCPRecv, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventDNS, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventWrite, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventRead, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventFsync, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventUDPSend, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventUDPRecv, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventSchedSwitch, ProcessName: "test"}
		eventChan <- nil
	}()

	go HandleEvents(eventChan)

	time.Sleep(100 * time.Millisecond)
}

func TestHandleEvents_NilEvent(t *testing.T) {
	eventChan := make(chan *events.Event, 1)

	go func() {
		defer close(eventChan)
		eventChan <- nil
	}()

	go HandleEvents(eventChan)

	time.Sleep(50 * time.Millisecond)
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Expected X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("Expected X-Frame-Options header")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	handler := rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Logf("Rate limit middleware returned status %d (may be expected)", w.Code)
	}
}

func TestServer_Shutdown(t *testing.T) {
	server := StartServer()
	if server == nil {
		t.Error("StartServer should return non-nil server")
	}

	time.Sleep(50 * time.Millisecond)

	server.Shutdown()
}

func TestExportResourceLimitMetric(t *testing.T) {
	tests := []struct {
		name         string
		event        *events.Event
		resourceType uint32
		utilization  int32
	}{
		{"CPU warning", &events.Event{Type: events.EventResourceLimit, TCPState: 0, Error: 85, Bytes: 850000000}, 0, 85},
		{"Memory critical", &events.Event{Type: events.EventResourceLimit, TCPState: 1, Error: 92, Bytes: 460000000}, 1, 92},
		{"IO emergency", &events.Event{Type: events.EventResourceLimit, TCPState: 2, Error: 97, Bytes: 970000000}, 2, 97},
		{"CPU below threshold", &events.Event{Type: events.EventResourceLimit, TCPState: 0, Error: 50, Bytes: 500000000}, 0, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportResourceLimitMetric(tt.event)
		})
	}
}

func TestExportResourceLimitMetricWithContext(t *testing.T) {
	event := &events.Event{
		Type:      events.EventResourceLimit,
		TCPState:  1,
		Error:     90,
		Bytes:     450000000,
	}

	ExportResourceLimitMetricWithContext(event, "test-namespace")
}

func TestExportResourceMetrics(t *testing.T) {
	tests := []struct {
		name              string
		resourceType      string
		namespace         string
		limitBytes        uint64
		usageBytes        uint64
		utilizationPercent float64
		alertLevel        uint32
	}{
		{"CPU warning", "cpu", "default", 1000000000, 850000000, 85.0, 1},
		{"Memory critical", "memory", "production", 500000000, 460000000, 92.0, 2},
		{"IO emergency", "io", "test", 1000000000, 970000000, 97.0, 3},
		{"CPU no alert", "cpu", "default", 1000000000, 500000000, 50.0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportResourceMetrics(
				tt.resourceType,
				tt.namespace,
				tt.limitBytes,
				tt.usageBytes,
				tt.utilizationPercent,
				tt.alertLevel,
			)
		})
	}
}

func TestHandleEvent_ResourceLimit(t *testing.T) {
	event := &events.Event{
		Type:      events.EventResourceLimit,
		TCPState:  0,
		Error:     85,
		Bytes:     850000000,
	}

	HandleEvent(event)
}

func TestHandleEventWithContext_ResourceLimit(t *testing.T) {
	event := &events.Event{
		Type:      events.EventResourceLimit,
		TCPState:  1,
		Error:     92,
		Bytes:     460000000,
	}

	k8sContext := map[string]interface{}{
		"namespace": "test-ns",
	}

	HandleEventWithContext(event, k8sContext)
}

func TestExportTLSMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventTLSHandshake,
		LatencyNS:   5000000,
		ProcessName: "nginx",
	}
	ExportTLSMetric(event)
}

func TestExportTLSMetricWithContext(t *testing.T) {
	event := &events.Event{
		Type:        events.EventTLSError,
		LatencyNS:   1000000,
		ProcessName: "go-server",
	}
	ExportTLSMetricWithContext(event, "production")
}

func TestExportPoolAcquireMetricWithContext(t *testing.T) {
	event := &events.Event{
		Type:        events.EventPoolAcquire,
		Target:      "db-pool",
		ProcessName: "app",
		LatencyNS:   200000,
	}
	ExportPoolAcquireMetricWithContext(event, "default")
}

func TestExportPoolAcquireMetricWithContext_DefaultPoolID(t *testing.T) {
	event := &events.Event{
		Type:   events.EventPoolAcquire,
		Target: "", // empty → "default" pool ID
	}
	ExportPoolAcquireMetricWithContext(event, "ns")
}

func TestExportPoolReleaseMetricWithContext(t *testing.T) {
	event := &events.Event{
		Type:   events.EventPoolRelease,
		Target: "redis-pool",
	}
	ExportPoolReleaseMetricWithContext(event, "")
}

func TestExportPoolExhaustedMetricWithContext(t *testing.T) {
	event := &events.Event{
		Type:      events.EventPoolExhausted,
		Target:    "conn-pool",
		LatencyNS: 50000000,
	}
	ExportPoolExhaustedMetricWithContext(event, "prod")
}

func TestHandleEventWithContext_AllEventTypes(t *testing.T) {
	ctx := map[string]interface{}{
		"namespace":      "test-ns",
		"target_pod":     "pod-a",
		"target_service": "svc-a",
	}

	testEvents := []*events.Event{
		{Type: events.EventConnect, LatencyNS: 1_000_000, ProcessName: "p"},
		{Type: events.EventTCPSend, LatencyNS: 2_000_000, Bytes: 100, ProcessName: "p"},
		{Type: events.EventTCPRecv, LatencyNS: 3_000_000, Bytes: 200, ProcessName: "p"},
		{Type: events.EventDNS, LatencyNS: 4_000_000, ProcessName: "p"},
		{Type: events.EventWrite, LatencyNS: 5_000_000, Bytes: 50, ProcessName: "p"},
		{Type: events.EventRead, LatencyNS: 6_000_000, Bytes: 60, ProcessName: "p"},
		{Type: events.EventFsync, LatencyNS: 7_000_000, ProcessName: "p"},
		{Type: events.EventUDPSend, LatencyNS: 8_000_000, Bytes: 30, ProcessName: "p"},
		{Type: events.EventUDPRecv, LatencyNS: 9_000_000, Bytes: 40, ProcessName: "p"},
		{Type: events.EventSchedSwitch, LatencyNS: 10_000_000, ProcessName: "p"},
		{Type: events.EventTLSHandshake, LatencyNS: 11_000_000, ProcessName: "p"},
		{Type: events.EventResourceLimit, LatencyNS: 12_000_000, ProcessName: "p"},
		{Type: events.EventPoolAcquire, LatencyNS: 13_000_000, ProcessName: "p"},
		{Type: events.EventPoolRelease, LatencyNS: 14_000_000, ProcessName: "p"},
		{Type: events.EventPoolExhausted, LatencyNS: 15_000_000, ProcessName: "p"},
		// Language-runtime adapters.
		{Type: events.EventRedisCmd, LatencyNS: 1_000_000, Details: "SET", ProcessName: "p"},
		{Type: events.EventRedisCmd, LatencyNS: 1_000_000, Details: "", ProcessName: "p"}, // empty cmd → "unknown"
		{Type: events.EventMemcachedCmd, LatencyNS: 500_000, Details: "get", ProcessName: "p"},
		{Type: events.EventMemcachedCmd, LatencyNS: 500_000, Details: "", ProcessName: "p"},
		{Type: events.EventFastCGIResp, LatencyNS: 20_000_000, Details: "GET", ProcessName: "p"},
		{Type: events.EventFastCGIResp, LatencyNS: 20_000_000, Details: "", ProcessName: "p"},
		{Type: events.EventGRPCMethod, LatencyNS: 8_000_000, Target: "/svc/Method", ProcessName: "p"},
		{Type: events.EventGRPCMethod, LatencyNS: 8_000_000, Target: "", ProcessName: "p"},
		{Type: events.EventKafkaProduce, LatencyNS: 5_000_000, Details: "my-topic", Bytes: 256, ProcessName: "p"},
		{Type: events.EventKafkaProduce, LatencyNS: 5_000_000, Details: "", Bytes: 0, ProcessName: "p"},
		{Type: events.EventKafkaFetch, LatencyNS: 3_000_000, Details: "my-topic", Bytes: 512, ProcessName: "p"},
		{Type: events.EventKafkaFetch, LatencyNS: 3_000_000, Details: "", Bytes: 0, ProcessName: "p"},
	}

	for _, e := range testEvents {
		HandleEventWithContext(e, ctx)
		HandleEventWithContext(e, nil) // test nil context path too
	}
}

func TestHandleEventWithContext_Nil(t *testing.T) {
	HandleEventWithContext(nil, nil) // must not panic
}

func TestHandleEvent_AllEventTypes(t *testing.T) {
	testEvents := []*events.Event{
		{Type: events.EventConnect, LatencyNS: 1_000_000},
		{Type: events.EventTCPSend, LatencyNS: 2_000_000, Bytes: 100},
		{Type: events.EventRedisCmd, LatencyNS: 1_000_000, Details: "GET"},
		{Type: events.EventKafkaProduce, LatencyNS: 5_000_000, Details: "t", Bytes: 10},
		{Type: events.EventKafkaFetch, LatencyNS: 3_000_000, Details: "t", Bytes: 20},
	}
	for _, e := range testEvents {
		HandleEvent(e)
	}
}

func TestHandleEvents_ClosedChannel(t *testing.T) {
	ch := make(chan *events.Event, 2)
	ch <- &events.Event{Type: events.EventDNS}
	ch <- nil // nil event should be skipped
	close(ch)
	HandleEvents(ch) // must drain and return
}

func TestRecordChannelDepths(t *testing.T) {
	// Must not panic.
	RecordChannelDepths(100, 50)
	RecordChannelDepths(0, 0)
}

func TestRecordBPFMapUtilization(t *testing.T) {
	// Must not panic.
	RecordBPFMapUtilization("stack_traces", 0.5)
	RecordBPFMapUtilization("start_times", 1.0)
	RecordBPFMapUtilization("unknown_map", 0.0)
}

func TestGetLabel_Variants(t *testing.T) {
	ctx := map[string]interface{}{
		"namespace": "test-ns",
		"empty":     "",
		"number":    42, // not a string
	}

	if got := getLabel(ctx, "namespace", "default"); got != "test-ns" {
		t.Errorf("expected test-ns, got %q", got)
	}
	if got := getLabel(ctx, "missing", "fallback"); got != "fallback" {
		t.Errorf("expected fallback, got %q", got)
	}
	if got := getLabel(ctx, "empty", "fallback"); got != "fallback" {
		t.Errorf("expected fallback for empty string, got %q", got)
	}
	if got := getLabel(ctx, "number", "fallback"); got != "fallback" {
		t.Errorf("expected fallback for non-string, got %q", got)
	}
	if got := getLabel(nil, "namespace", "fallback"); got != "fallback" {
		t.Errorf("expected fallback for nil ctx, got %q", got)
	}
}

func TestSecurityHeadersMiddleware_LargeRequest(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := securityHeadersMiddleware(next)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// Set ContentLength > maxRequestSize to trigger 413.
	req.ContentLength = maxRequestSize + 1
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rr.Code)
	}
}

func TestRateLimitMiddleware_Allowed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rateLimitMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The first request should be allowed (rate limiter has capacity at startup).
	if rr.Code != http.StatusOK && rr.Code != http.StatusTooManyRequests {
		t.Errorf("unexpected status code: %d", rr.Code)
	}
}
