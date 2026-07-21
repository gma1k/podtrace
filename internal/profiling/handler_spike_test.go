package profiling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func TestHandler_Run_TriggerChannel(t *testing.T) {
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
	h := NewHandler(host, []int{port})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *events.Event)
	go h.Run(ctx, ch)

	h.TriggerNow(ProfileHeap, 0)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if res := h.GetResult(); res != nil && res.HeapProfile != nil && res.HeapProfile.Available {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("expected Handler.Run to service the trigger and store a heap result")
}

func TestCheckSpike_NonSlowEventType(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	h.checkSpike(context.Background(), &events.Event{
		Type:      events.EventPageFault,
		LatencyNS: uint64(config.ProfilingAutoTriggerMS*float64(config.NSPerMS)) + 1,
	})
	if h.triggered.Load() {
		t.Error("non-slow event type must not auto-trigger profiling")
	}
}

func TestCheckSpike_BelowThreshold(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	h.checkSpike(context.Background(), &events.Event{
		Type:      events.EventTCPSend,
		LatencyNS: 1,
	})
	if h.triggered.Load() {
		t.Error("sub-threshold latency must not auto-trigger profiling")
	}
}

func TestHandler_GenerateSection_PprofFromDiscovery(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{6060})
	h.profiler.foundPort.Store(6060)
	out := h.GenerateSection([]*events.Event{}, time.Second)
	if !contains(out, "available") {
		t.Errorf("expected 'available' pprof notice when a port was discovered, got:\n%s", out)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
