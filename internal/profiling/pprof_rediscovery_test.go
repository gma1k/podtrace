package profiling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestDiscoverDoesNotPinAPortThatAnswersEveryPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>my single page app</body></html>"))
	}))
	t.Cleanup(srv.Close)
	host, port := mustParseAddr(t, srv.Listener.Addr().String())

	p := NewPodProfiler(host, []int{port})
	if p.Discover(context.Background()) {
		t.Fatalf("Discover pinned port %d, which serves no pprof index", port)
	}
}

func lateStartingPprof(t *testing.T) (*PodProfiler, *atomic.Bool, *atomic.Int64) {
	t.Helper()
	var live atomic.Bool
	var probes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/pprof/" {
			probes.Add(1)
		}
		if !live.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/debug/pprof/" {
			_, _ = w.Write([]byte(pprofIndexPage))
			return
		}
		_, _ = w.Write([]byte("goroutine 1 [running]:\nmain.main()\n"))
	}))
	t.Cleanup(srv.Close)
	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	return NewPodProfiler(host, []int{port}), &live, &probes
}

func TestAFetchRetriesDiscoveryOnceTheIntervalHasPassed(t *testing.T) {
	p, live, _ := lateStartingPprof(t)
	if p.Discover(context.Background()) {
		t.Fatal("discovery succeeded before the listener started")
	}
	live.Store(true)

	p.discoverMu.Lock()
	p.lastDiscovery = time.Now().Add(-pprofRediscoveryInterval)
	p.discoverMu.Unlock()

	r := p.FetchGoroutine(context.Background())
	if !r.Available || r.GoroutineCount != 1 {
		t.Fatalf("FetchGoroutine = %+v, want the listener found by rediscovery", r)
	}
}

func TestAFetchDoesNotReprobeBeforeTheInterval(t *testing.T) {
	p, live, probes := lateStartingPprof(t)
	p.Discover(context.Background())
	live.Store(true)
	before := probes.Load()

	if r := p.FetchHeap(context.Background()); r.Available {
		t.Fatal("fetch found an endpoint without rediscovering")
	}
	if got := probes.Load(); got != before {
		t.Fatalf("probed %d more times inside the rediscovery interval", got-before)
	}
}

func TestTheFirstFetchDiscoversWhenDiscoverWasNeverRun(t *testing.T) {
	p, live, _ := lateStartingPprof(t)
	live.Store(true)
	if r := p.FetchGoroutine(context.Background()); !r.Available {
		t.Fatalf("FetchGoroutine = %+v, want discovery on first use", r)
	}
}

func TestDiscoveredPortWithoutAPodIPIsZero(t *testing.T) {
	if port := NewPodProfiler("", []int{6060}).discoveredPort(context.Background()); port != 0 {
		t.Fatalf("discoveredPort = %d, want 0 without a pod IP", port)
	}
}

func TestProbeRejectsAnIndexThatFailsToRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("goroutine heap"))
	}))
	t.Cleanup(srv.Close)
	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	if p.Discover(context.Background()) {
		t.Fatal("Discover accepted a truncated index body")
	}
}

func TestProbeRejectsAnUnbuildableRequest(t *testing.T) {
	p := NewPodProfiler("10.0.0.1", nil)
	var nilCtx context.Context
	if p.probePprofIndex(nilCtx, p.httpClient, 6060) {
		t.Fatal("probe succeeded without a request")
	}
}

func TestDiscoveryFoundByAnotherCallerIsNotRepeated(t *testing.T) {
	p := NewPodProfiler("10.0.0.1", []int{6060})
	p.foundPort.Store(6060)
	p.discoverMu.Lock()
	defer p.discoverMu.Unlock()
	if !p.discoverLocked(context.Background()) || !p.lastDiscovery.IsZero() {
		t.Fatal("a known port must short-circuit discovery")
	}
}

func slowSpike() *events.Event {
	return &events.Event{Type: events.EventHTTPResp, LatencyNS: uint64(10 * time.Second)}
}

func waitForHeap(t *testing.T, h *Handler, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r := h.GetResult()
		if r != nil && r.HeapProfile != nil && r.HeapProfile.Available == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("heap availability never became %v: %+v", want, h.GetResult())
}

func TestAPprofListenerStartedAfterTheFirstSpikeIsStillProfiled(t *testing.T) {
	p, live, _ := lateStartingPprof(t)
	h := newHandler(p.podIP, p.ports, make(chan struct{}, 1), 1)
	h.profiler = p
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.profiler.Discover(ctx)
	h.startWorkers(ctx)

	h.checkSpike(ctx, slowSpike())
	waitForHeap(t, h, false)

	live.Store(true)
	h.checkSpike(ctx, slowSpike())
	if !h.missedEndpoint.Load() {
		t.Fatal("a retry inside the rediscovery interval consumed the missed endpoint")
	}

	p.discoverMu.Lock()
	p.lastDiscovery = time.Now().Add(-pprofRediscoveryInterval)
	p.discoverMu.Unlock()
	h.checkSpike(ctx, slowSpike())
	waitForHeap(t, h, true)
}

func TestRediscoveryIsNotDueOnceAnEndpointIsKnownOrWithoutAPod(t *testing.T) {
	known := NewPodProfiler("10.0.0.1", []int{6060})
	known.foundPort.Store(6060)
	if known.rediscoveryDue() {
		t.Error("rediscovery due with a known endpoint")
	}
	if NewPodProfiler("", []int{6060}).rediscoveryDue() {
		t.Error("rediscovery due without a pod IP")
	}
	if !NewPodProfiler("10.0.0.1", []int{6060}).rediscoveryDue() {
		t.Error("rediscovery not due before any attempt")
	}
}
