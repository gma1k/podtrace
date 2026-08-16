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

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

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

func TestServeManagementAPI_WithProfilingController(t *testing.T) {
	ctrl := &fakeProfilingController{}
	tr := &Tracer{
		probeGroups:   map[probes.ProbeGroup][]link.Link{},
		profilingCtrl: ctrl,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tr.serveManagementAPI(ctx, 0)
		close(done)
	}()
	cancel()
	<-done
}

func TestSetContainerIDs_AllEmpty(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{}}}
	err := tr.SetContainerIDs([]string{"", "", ""})
	if err == nil {
		t.Fatal("expected error for all-blank container IDs")
		return
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

func TestSetContainerIDs_PicksFirstNonEmpty(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{}}}
	if err := tr.SetContainerIDs([]string{"", "abc123def456", ""}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if tr.lastContainerID() != "abc123def456" {
		t.Errorf("containerID = %q, want abc123def456", tr.lastContainerID())
	}
}

func TestActiveProbeGroups_StableOrder(t *testing.T) {
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
