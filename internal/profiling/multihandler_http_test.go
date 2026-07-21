package profiling

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func TestMultiHandler_Run_CtxCancel(t *testing.T) {
	m := NewMultiHandler([]string{"127.0.0.1"}, []int{1})
	ch := make(chan *events.Event)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx, ch)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("MultiHandler.Run did not exit after context cancel")
	}
}

func TestMultiHandler_Run_ClosedChannel(t *testing.T) {
	m := NewMultiHandler([]string{"127.0.0.1"}, []int{1})
	ch := make(chan *events.Event)
	close(ch)
	done := make(chan struct{})
	go func() {
		m.Run(context.Background(), ch)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("MultiHandler.Run did not exit when channel closed")
	}
}

func TestMultiHandler_Run_TriggerProfilesAllPods(t *testing.T) {
	const heapText = `heap profile: 1: 1024 [1: 1024] @ heap/1048576
1: 1024 [1: 1024] @
#	0x0	example.com/pkg.Alloc+0x0	file.go:1

`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(heapText))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	m := NewMultiHandler([]string{host}, []int{port})
	if m.Len() != 1 {
		t.Fatalf("expected 1 handler, got %d", m.Len())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *events.Event)
	go m.Run(ctx, ch)

	req := httptest.NewRequest(http.MethodPost, "/profile/start?type=heap", nil)
	rr := httptest.NewRecorder()
	m.HTTPStart(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202 from HTTPStart, got %d", rr.Code)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if res := m.handlers[0].GetResult(); res != nil && res.HeapProfile != nil && res.HeapProfile.Available {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("expected sub-handler to store an available heap result after trigger")
}

func TestMultiHandler_Run_SpikeTriggersProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(""))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	m := NewMultiHandler([]string{host}, []int{port})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *events.Event, 4)
	go m.Run(ctx, ch)
	time.Sleep(50 * time.Millisecond)

	triggerNS := uint64(config.ProfilingAutoTriggerMS*float64(config.NSPerMS)) + 1
	ch <- &events.Event{Type: events.EventTCPSend, LatencyNS: triggerNS}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.handlers[0].triggered.Load() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("expected sub-handler to auto-trigger after a latency-spike event")
}

func TestMultiHandler_HTTPStart_MethodNotAllowed(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1"}, []int{6060})
	req := httptest.NewRequest(http.MethodGet, "/profile/start", nil)
	rr := httptest.NewRecorder()
	m.HTTPStart(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestMultiHandler_HTTPStart_DefaultType(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2"}, []int{6060})
	req := httptest.NewRequest(http.MethodPost, "/profile/start", nil)
	rr := httptest.NewRecorder()
	m.HTTPStart(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["type"] != "heap" {
		t.Errorf("expected default type=heap, got %v", body["type"])
	}
	if body["pods"].(float64) != 2 {
		t.Errorf("expected pods=2, got %v", body["pods"])
	}
}

func TestMultiHandler_HTTPStart_CPUAndGoroutineAndInvalidDuration(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		{"?type=cpu&duration=5s", "cpu"},
		{"?type=goroutine", "goroutine"},
		{"?type=bogus", "heap"},
		{"?duration=notaduration", "heap"},
	}
	for _, c := range cases {
		m := NewMultiHandler([]string{"10.0.0.1"}, []int{6060})
		req := httptest.NewRequest(http.MethodPost, "/profile/start"+c.query, nil)
		rr := httptest.NewRecorder()
		m.HTTPStart(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Errorf("%s: expected 202, got %d", c.query, rr.Code)
			continue
		}
		var body map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
			t.Errorf("%s: decode failed: %v", c.query, err)
			continue
		}
		if body["type"] != c.want {
			t.Errorf("%s: expected type=%q, got %v", c.query, c.want, body["type"])
		}
	}
}

func TestMultiHandler_HTTPStart_ChannelFullIsNonBlocking(t *testing.T) {

	m := NewMultiHandler([]string{"10.0.0.1"}, []int{6060})
	for i := 0; i < config.ProfilingMaxConcurrent+2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/profile/start", nil)
		rr := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			m.HTTPStart(rr, req)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("HTTPStart blocked when trigger channel was full")
		}
		if rr.Code != http.StatusAccepted {
			t.Errorf("expected 202 even when channel full, got %d", rr.Code)
		}
	}
}

func TestMultiHandler_HTTPStatus_MethodNotAllowed(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1"}, []int{6060})
	req := httptest.NewRequest(http.MethodPost, "/profile/status", nil)
	rr := httptest.NewRecorder()
	m.HTTPStatus(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestMultiHandler_HTTPStatus_PerPodArray(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2"}, []int{6060})
	req := httptest.NewRequest(http.MethodGet, "/profile/status", nil)
	rr := httptest.NewRecorder()
	m.HTTPStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body struct {
		Pods     int                      `json:"pods"`
		Statuses []map[string]interface{} `json:"statuses"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if body.Pods != 2 {
		t.Errorf("expected pods=2, got %d", body.Pods)
	}
	if len(body.Statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(body.Statuses))
	}
	if body.Statuses[0]["pod_ip"] != "10.0.0.1" {
		t.Errorf("expected first status pod_ip=10.0.0.1, got %v", body.Statuses[0]["pod_ip"])
	}
}

func TestMultiHandler_HTTPResult_MethodNotAllowed(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1"}, []int{6060})
	req := httptest.NewRequest(http.MethodPost, "/profile/result", nil)
	rr := httptest.NewRecorder()
	m.HTTPResult(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestMultiHandler_HTTPResult_NoContentWhenEmpty(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2"}, []int{6060})
	req := httptest.NewRequest(http.MethodGet, "/profile/result", nil)
	rr := httptest.NewRecorder()
	m.HTTPResult(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 when no pod has a result, got %d", rr.Code)
	}
}

func TestMultiHandler_HTTPResult_OmitsPodsWithoutResult(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2"}, []int{6060})

	h := m.handlers[0]
	h.mu.Lock()
	h.result = &CorrelatedResult{
		PprofAvailable:  true,
		PodIP:           "10.0.0.1",
		PageFaultCounts: map[uint32]int{7: 3},
		GoroutineProfile: &ProfileResult{
			Available:      true,
			GoroutineCount: 9,
			BlockedCount:   2,
		},
	}
	h.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/profile/result", nil)
	rr := httptest.NewRecorder()
	m.HTTPResult(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body struct {
		Pods    int                      `json:"pods"`
		Results []map[string]interface{} `json:"results"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if body.Pods != 2 {
		t.Errorf("expected pods=2, got %d", body.Pods)
	}

	if len(body.Results) != 1 {
		t.Fatalf("expected 1 result (pods without a result are omitted), got %d", len(body.Results))
	}
	if body.Results[0]["pod_ip"] != "10.0.0.1" {
		t.Errorf("expected result for pod 10.0.0.1, got %v", body.Results[0]["pod_ip"])
	}
	if body.Results[0]["goroutine_count"].(float64) != 9 {
		t.Errorf("expected goroutine_count=9, got %v", body.Results[0]["goroutine_count"])
	}
}
