package tracer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func prefilterMaps(t *testing.T) *ebpf.Collection {
	t.Helper()
	flag, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	targets, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{
		"cgroup_filter_enabled": flag,
		"target_cgroup_ids":     targets,
	}}
	t.Cleanup(coll.Close)
	return coll
}

func prefilterEnabled(t *testing.T, coll *ebpf.Collection) bool {
	t.Helper()
	var on uint32
	if err := coll.Maps["cgroup_filter_enabled"].Lookup(uint32(0), &on); err != nil {
		t.Fatal(err)
	}
	return on == 1
}

func TestKernelPrefilterStaysOnWhenNoTargetResolves(t *testing.T) {
	base := cgroupV2Base(t)
	tr := gateTestTracer()
	tr.collection = prefilterMaps(t)

	if err := tr.AttachToCgroups([]string{filepath.Join(base, "kubepods", "pod-gone")}); err != nil {
		t.Fatal(err)
	}
	if !prefilterEnabled(t, tr.collection) {
		t.Fatal("the kernel prefilter switched off for the whole node because the only target's cgroup is gone")
	}
}

func TestKernelPrefilterFollowsTheTargetLifecycle(t *testing.T) {
	base := cgroupV2Base(t)
	container := filepath.Join(base, "kubepods.slice", testPodSlice, "cri-containerd-aaaa.scope")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	tr := gateTestTracer()
	tr.collection = prefilterMaps(t)

	if err := tr.AttachToCgroups([]string{container}); err != nil {
		t.Fatal(err)
	}
	if !prefilterEnabled(t, tr.collection) {
		t.Fatal("a resolved target did not switch the kernel prefilter on")
	}

	if err := tr.SetCgroups(nil); err != nil {
		t.Fatal(err)
	}
	if prefilterEnabled(t, tr.collection) {
		t.Fatal("with no targets and no deny mode the prefilter must let everything through")
	}

	tr.SetDenyWhenNoTargets(true)
	if err := tr.SetCgroups(nil); err != nil {
		t.Fatal(err)
	}
	if !prefilterEnabled(t, tr.collection) {
		t.Fatal("an idle agent in deny mode must keep the prefilter on with an empty set")
	}
}

func TestKernelInheritedChildOfAWithdrawnPodIsNotAdmitted(t *testing.T) {
	inherited, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{inheritedCgroupMapName: inherited}}}
	t.Cleanup(tr.collection.Close)
	if err := inherited.Put(uint64(777), uint64(50)); err != nil {
		t.Fatal(err)
	}
	if err := inherited.Put(uint64(778), uint64(60)); err != nil {
		t.Fatal(err)
	}
	tr.inheritedParents.Store(&map[uint64]struct{}{60: {}})

	if _, ok := tr.InheritedCgroupParent(777); ok {
		t.Error("a kernel entry left under a withdrawn pod was admitted")
	}
	if _, cached := tr.inheritedCache.Load(uint64(777)); cached {
		t.Error("a kernel entry left under a withdrawn pod was cached")
	}
	if parent, ok := tr.InheritedCgroupParent(778); !ok || parent != 60 {
		t.Errorf("InheritedCgroupParent(778) = %d, %v; want 60, true", parent, ok)
	}
}
