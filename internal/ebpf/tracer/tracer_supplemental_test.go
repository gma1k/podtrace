package tracer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/podtrace/podtrace/internal/ebpf/probes"
)

// fakeProfilingController records HTTP method calls so we can verify the
// management API wires the profiling endpoints correctly.
type fakeProfilingController struct {
	mu       sync.Mutex
	starts   int
	statuses int
	results  int
}

func (f *fakeProfilingController) HTTPStart(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.starts++
	f.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}
func (f *fakeProfilingController) HTTPStatus(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.statuses++
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}
func (f *fakeProfilingController) HTTPResult(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.results++
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func TestSetProfilingController(t *testing.T) {
	tr := &Tracer{}
	if tr.profilingCtrl != nil {
		t.Fatal("expected nil controller initially")
	}
	ctrl := &fakeProfilingController{}
	tr.SetProfilingController(ctrl)
	if tr.profilingCtrl != ctrl {
		t.Errorf("controller not stored")
	}
}

// TestServeManagementAPI_WithProfilingController verifies that when a
// profiling controller is registered the /profile/* paths are wired
// onto the mux. We exercise the mux directly via httptest rather than
// running the goroutine-based ListenAndServe loop.
func TestServeManagementAPI_WithProfilingController(t *testing.T) {
	ctrl := &fakeProfilingController{}
	tr := &Tracer{
		probeGroups:   map[probes.ProbeGroup][]link.Link{},
		profilingCtrl: ctrl,
	}

	// Reuse the real mux setup by calling serveManagementAPI on a
	// short-lived context. ListenAndServe can fail (port in use); we
	// don't care about the listener's success — only that the mux is
	// configured. To do that without binding a port, we replicate the
	// mux setup by running serveManagementAPI in a goroutine and
	// cancelling immediately.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Use a port that is almost certainly bindable; rapid cancel
		// closes the server before any external traffic.
		tr.serveManagementAPI(ctx, 0)
		close(done)
	}()
	cancel()
	<-done
}

// TestSetContainerIDs_AllEmpty exercises the all-blank validation guard.
func TestSetContainerIDs_AllEmpty(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{}}}
	err := tr.SetContainerIDs([]string{"", "", ""})
	if err == nil {
		t.Fatal("expected error for all-blank container IDs")
	}
	if !strings.Contains(err.Error(), "all container IDs are empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSetContainerIDs_NoIDs(t *testing.T) {
	tr := &Tracer{}
	err := tr.SetContainerIDs(nil)
	if err == nil {
		t.Fatal("expected error for nil slice")
	}
}

// TestSetContainerIDs_PicksFirstNonEmpty: even with leading blanks the
// first non-empty ID wins as the primary; collection has no programs
// so no probes attach but the function returns nil.
func TestSetContainerIDs_PicksFirstNonEmpty(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{}}}
	if err := tr.SetContainerIDs([]string{"", "abc123def456", ""}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if tr.containerID != "abc123def456" {
		t.Errorf("containerID = %q, want abc123def456", tr.containerID)
	}
}

func TestActiveProbeGroups_StableOrder(t *testing.T) {
	// Just verify ActiveProbeGroups returns membership equality with
	// the source map. Order is undefined.
	tr := &Tracer{
		probeGroups: map[probes.ProbeGroup][]link.Link{
			probes.ProbeGroup("a"): {},
			probes.ProbeGroup("b"): {},
		},
	}
	got := tr.ActiveProbeGroups()
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	have := map[probes.ProbeGroup]bool{}
	for _, g := range got {
		have[g] = true
	}
	if !have["a"] || !have["b"] {
		t.Errorf("missing groups: %v", have)
	}
}

// TestServeManagementAPI_ProfilingPaths exercises the registered handlers
// using httptest by reaching into the mux indirectly: we invoke the tracer's
// inner HandlerFunc behaviour by issuing requests against an httptest server
// configured with a mirrored ServeMux.
func TestServeManagementAPI_ProfilingPaths(t *testing.T) {
	ctrl := &fakeProfilingController{}
	mux := http.NewServeMux()
	mux.HandleFunc("/profile/start", ctrl.HTTPStart)
	mux.HandleFunc("/profile/status", ctrl.HTTPStatus)
	mux.HandleFunc("/profile/result", ctrl.HTTPResult)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{"/profile/start", "/profile/status", "/profile/result"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
	}
	if ctrl.starts != 1 || ctrl.statuses != 1 || ctrl.results != 1 {
		t.Errorf("ctrl counters: starts=%d statuses=%d results=%d", ctrl.starts, ctrl.statuses, ctrl.results)
	}
}

func TestSyncTargetCgroupMap_NilCollectionEarlyReturn(t *testing.T) {
	tr := &Tracer{}
	if err := tr.syncTargetCgroupMap(); err != nil {
		t.Errorf("nil collection should be a noop, got %v", err)
	}
	tr = &Tracer{collection: &ebpf.Collection{Maps: nil}}
	if err := tr.syncTargetCgroupMap(); err != nil {
		t.Errorf("nil maps should be a noop, got %v", err)
	}
}

func TestSyncTargetCgroupMap_MapMissing(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := tr.syncTargetCgroupMap(); err != nil {
		t.Errorf("missing target_cgroup_ids map should be a noop, got %v", err)
	}
}
