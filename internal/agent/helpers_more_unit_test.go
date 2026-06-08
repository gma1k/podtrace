package agent

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// TestMetricsEngineObserver_AttachDetach exercises the engine observer
// adapter returned by Metrics.EngineObserver: positive deltas land on the
// cgroups_attached/detached counters, and non-positive deltas are ignored.
func TestMetricsEngineObserver_AttachDetach(t *testing.T) {
	m := NewMetrics()
	obs := m.EngineObserver()
	if obs == nil {
		t.Fatal("EngineObserver returned nil")
	}

	obs.OnCgroupsAttached(0)
	obs.OnCgroupsAttached(-3)
	obs.OnCgroupsDetached(0)
	obs.OnCgroupsDetached(-1)
	if got := scrapeMetric(t, m, `cgroups_attached_total`); got != 0 {
		t.Errorf("non-positive attach delta changed counter: %d", got)
	}
	if got := scrapeMetric(t, m, `cgroups_detached_total`); got != 0 {
		t.Errorf("non-positive detach delta changed counter: %d", got)
	}

	obs.OnCgroupsAttached(4)
	obs.OnCgroupsAttached(2)
	obs.OnCgroupsDetached(3)
	if got := scrapeMetric(t, m, `cgroups_attached_total`); got != 6 {
		t.Errorf("cgroups_attached_total = %d, want 6", got)
	}
	if got := scrapeMetric(t, m, `cgroups_detached_total`); got != 3 {
		t.Errorf("cgroups_detached_total = %d, want 3", got)
	}
}

// TestIsNetworkLatencyEvent covers every recognized network-latency event
// type plus a representative negative case.
func TestIsNetworkLatencyEvent(t *testing.T) {
	trueCases := []events.EventType{
		events.EventConnect,
		events.EventTCPSend,
		events.EventTCPRecv,
		events.EventUDPSend,
		events.EventUDPRecv,
	}
	for _, et := range trueCases {
		if !isNetworkLatencyEvent(et) {
			t.Errorf("isNetworkLatencyEvent(%v) = false, want true", et)
		}
	}
	for _, et := range []events.EventType{events.EventDNS, events.EventOpen} {
		if isNetworkLatencyEvent(et) {
			t.Errorf("isNetworkLatencyEvent(%v) = true, want false", et)
		}
	}
}

// TestContainerStatusIndex_BuildsFromAllStatusLists asserts the index keys
// off the runtime-stripped container ID and spans regular, init, and
// ephemeral container statuses while dropping incomplete entries.
func TestContainerStatusIndex_BuildsFromAllStatusLists(t *testing.T) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://aaaa1111"},
				{Name: "noid"},                                // missing ID → skipped
				{Name: "", ContainerID: "crio://bb"},          // missing name → skipped
				{Name: "empty", ContainerID: "containerd://"}, // empty after scheme → skipped
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "init", ContainerID: "docker://cccc3333"},
			},
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				{Name: "debug", ContainerID: "containerd://dddd4444"},
			},
		},
	}

	idx := containerStatusIndex(p)
	want := map[string]string{
		"aaaa1111": "app",
		"cccc3333": "init",
		"dddd4444": "debug",
	}
	if len(idx) != len(want) {
		t.Fatalf("index size = %d, want %d (%v)", len(idx), len(want), idx)
	}
	for id, name := range want {
		if idx[id] != name {
			t.Errorf("idx[%q] = %q, want %q", id, idx[id], name)
		}
	}
}

// TestIdentifyContainerCgroup covers the reachable matching branches:
// per-runtime prefix stripping, prefix-on-either-side matching, the
// empty-index short-circuit, and the no-match fall-through. The function is
// pure (operates on the dir string + an in-memory index), so no live cgroup
// state is required.
func TestIdentifyContainerCgroup(t *testing.T) {
	statuses := map[string]string{
		"aaaa1111bbbb2222": "app",
		"ffff9999":         "side",
	}

	cases := []struct {
		name     string
		dir      string
		statuses map[string]string
		wantName string
		wantID   string
	}{
		{
			name:     "cri-containerd prefix, dir is prefix of full id",
			dir:      "cri-containerd-aaaa1111.scope",
			statuses: statuses,
			wantName: "app",
			wantID:   "aaaa1111bbbb2222",
		},
		{
			name:     "crio prefix, full id is prefix of dir",
			dir:      "crio-ffff9999extra.scope",
			statuses: statuses,
			wantName: "side",
			wantID:   "ffff9999",
		},
		{
			name:     "docker prefix exact match",
			dir:      "docker-ffff9999.scope",
			statuses: statuses,
			wantName: "side",
			wantID:   "ffff9999",
		},
		{
			name:     "empty index short-circuits",
			dir:      "cri-containerd-aaaa1111.scope",
			statuses: map[string]string{},
			wantName: "",
			wantID:   "",
		},
		{
			name:     "no matching container",
			dir:      "cri-containerd-deadbeef.scope",
			statuses: statuses,
			wantName: "",
			wantID:   "",
		},
		{
			name:     "bare prefix leaves empty trimmed id",
			dir:      "crio-.scope",
			statuses: statuses,
			wantName: "",
			wantID:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, id := identifyContainerCgroup(tc.dir, tc.statuses)
			if name != tc.wantName || id != tc.wantID {
				t.Errorf("identifyContainerCgroup(%q) = (%q, %q), want (%q, %q)",
					tc.dir, name, id, tc.wantName, tc.wantID)
			}
		})
	}
}

// TestAttachMetricsObserver_OnAttachFailure asserts the observer records a
// program_attach_failures_total series classified by the backend error, and
// that nil receivers/metrics are safe no-ops (probe wiring contract).
func TestAttachMetricsObserver_OnAttachFailure(t *testing.T) {
	m := NewMetrics()
	obs := &attachMetricsObserver{metrics: m}

	obs.OnAttachFailure("kprobe_vfs_open", "vfs_open", true, errors.New("operation not permitted"))
	if got := scrapeMetric(t, m,
		`program_attach_failures_total{program="kprobe_vfs_open",reason="permission_denied"}`); got != 1 {
		t.Errorf("OnAttachFailure did not record permission_denied series; got %d", got)
	}

	(&attachMetricsObserver{metrics: nil}).OnAttachFailure("p", "s", false, errors.New("x"))
	var nilObs *attachMetricsObserver
	nilObs.OnAttachFailure("p", "s", false, errors.New("x"))
}

// TestNoopBackend_SetCgroups verifies SetCgroups replaces the attached set
// from the supplied targets, skipping entries with an empty CgroupPath.
func TestNoopBackend_SetCgroups(t *testing.T) {
	b := newNoopBackend()
	if err := b.AttachToCgroup("/stale"); err != nil {
		t.Fatal(err)
	}

	err := b.SetCgroups([]tracer.CgroupTarget{
		{CgroupPath: "/c/a", ContainerID: "id-a"},
		{CgroupPath: "", ContainerID: "skip-me"},
		{CgroupPath: "/c/b"},
	})
	if err != nil {
		t.Fatalf("SetCgroups: %v", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.attached) != 2 {
		t.Fatalf("attached = %v, want exactly /c/a and /c/b", b.attached)
	}
	if _, ok := b.attached["/c/a"]; !ok {
		t.Error("/c/a missing from attached set")
	}
	if _, ok := b.attached["/c/b"]; !ok {
		t.Error("/c/b missing from attached set")
	}
	if _, ok := b.attached["/stale"]; ok {
		t.Error("SetCgroups should have replaced the prior attached set")
	}
	if _, ok := b.attached[""]; ok {
		t.Error("empty CgroupPath should be skipped")
	}
}
