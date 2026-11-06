package tracer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/events"
)

const testPodSlice = "kubepods-besteffort-pod030a9a31_6d1e_4b0e_9b51_5a7c8b2f3e41.slice"

func cgroupV2Base(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu memory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := config.CgroupBasePath
	config.CgroupBasePath = base
	t.Cleanup(func() { config.CgroupBasePath = prev })
	return base
}

func gateTestTracer() *Tracer {
	tr := newDispatchTestTracer()
	tr.filter = filter.NewCgroupFilter()
	tr.useUserspaceCgroupFilter.Store(true)
	tr.resourceMgr = newResourceMonitorManager()
	return tr
}

func TestATargetWhosePathNoLongerExistsAdmitsNothingByCgroupID(t *testing.T) {
	base := cgroupV2Base(t)
	tr := gateTestTracer()

	if err := tr.AttachToCgroups([]string{filepath.Join(base, "kubepods", "pod-gone")}); err != nil {
		t.Fatal(err)
	}
	if !tr.cgroupIDsAuthoritative.Load() || len(tr.loadCgroupIDs()) != 0 {
		t.Fatalf("authoritative = %v, ids = %v; want the id gate on with an empty set",
			tr.cgroupIDsAuthoritative.Load(), tr.loadCgroupIDs())
	}
	for _, ev := range []*events.Event{
		{Type: events.EventTCPState, PID: 0, CgroupID: 4242},
		{Type: events.EventTCPSend, PID: uint32(os.Getpid()), CgroupID: 4242},
	} {
		if dispatchConfined(t, tr, ev) {
			t.Errorf("an event from cgroup %d (pid %d) was admitted although no target resolved to a cgroup", ev.CgroupID, ev.PID)
		}
		if tr.cgroupAllows(ev) {
			t.Errorf("cgroupAllows admitted cgroup %d although the dispatch gate refuses it", ev.CgroupID)
		}
	}
}

func TestAPIDlessEventFromAResolvedTargetIsAdmitted(t *testing.T) {
	base := cgroupV2Base(t)
	container := filepath.Join(base, "kubepods.slice", testPodSlice, "cri-containerd-aaaa.scope")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := getCgroupIDFromPath(container)
	if err != nil {
		t.Fatal(err)
	}
	tr := gateTestTracer()
	if err := tr.AttachToCgroups([]string{container}); err != nil {
		t.Fatal(err)
	}

	if !dispatchConfined(t, tr, &events.Event{Type: events.EventTCPRTT, PID: 0, CgroupID: id}) {
		t.Fatal("a sock_ops RTT sample from the targeted container was dropped")
	}
	if dispatchConfined(t, tr, &events.Event{Type: events.EventTCPRTT, PID: 0, CgroupID: id + 1000}) {
		t.Fatal("a sock_ops RTT sample from an untargeted cgroup was admitted")
	}
}

func TestDetachingEveryTargetStopsMonitorsAndForgetsInheritedContainers(t *testing.T) {
	base := cgroupV2Base(t)
	pod := filepath.Join(base, "kubepods.slice", testPodSlice)
	container := filepath.Join(pod, "cri-containerd-aaaa.scope")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	podID, err := getCgroupIDFromPath(pod)
	if err != nil {
		t.Fatal(err)
	}
	tr := gateTestTracer()
	monitors := activateWithFakes(tr.resourceMgr)
	if err := tr.AttachToCgroups([]string{container}); err != nil {
		t.Fatal(err)
	}
	if monitors[container] == nil {
		t.Fatal("attaching a target did not start its resource monitor")
	}
	tr.inheritedCache.Store(uint64(777), podID)
	if _, ok := tr.InheritedCgroupParent(777); !ok {
		t.Fatal("a container created under the targeted pod was not inherited")
	}

	if err := tr.SetCgroups(nil); err != nil {
		t.Fatal(err)
	}

	if !monitors[container].isStopped() || tr.resourceMgr.runningCount() != 0 {
		t.Error("a resource monitor for a withdrawn target kept running and alerting")
	}
	if _, ok := tr.InheritedCgroupParent(777); ok {
		t.Error("a container of a withdrawn pod is still inherited")
	}
	if tr.cgroupIDsAuthoritative.Load() {
		t.Error("with no target the id gate must give way to the idle rules")
	}
}

func TestAPrunedInheritanceIsNotRelearnedByALateCacheWrite(t *testing.T) {
	base := cgroupV2Base(t)
	pod := filepath.Join(base, "kubepods.slice", testPodSlice)
	container := filepath.Join(pod, "cri-containerd-aaaa.scope")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	podID, err := getCgroupIDFromPath(pod)
	if err != nil {
		t.Fatal(err)
	}
	tr := gateTestTracer()
	tr.syncCgroupInheritance([]string{container})
	tr.syncCgroupInheritance(nil)
	tr.inheritedCache.Store(uint64(777), podID)

	if _, ok := tr.InheritedCgroupParent(777); ok {
		t.Fatal("a lookup that raced the prune re-learned a child of a pod no longer targeted")
	}
	if _, cached := tr.inheritedCache.Load(uint64(777)); cached {
		t.Fatal("the stale mapping stayed in the cache")
	}
}

func TestAnInheritedContainerOfAStillTargetedPodIsKept(t *testing.T) {
	base := cgroupV2Base(t)
	pod := filepath.Join(base, "kubepods.slice", testPodSlice)
	container := filepath.Join(pod, "cri-containerd-aaaa.scope")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	podID, err := getCgroupIDFromPath(pod)
	if err != nil {
		t.Fatal(err)
	}
	tr := gateTestTracer()
	tr.syncCgroupInheritance([]string{container})
	tr.inheritedCache.Store(uint64(777), podID)

	if parent, ok := tr.InheritedCgroupParent(777); !ok || parent != podID {
		t.Fatalf("InheritedCgroupParent = %d, %v; want %d, true", parent, ok, podID)
	}
}
