package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
)

func sharedLRUSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"start_times":          {Type: ebpf.LRUHash, MaxEntries: 4096},
		"inherited_cgroup_ids": {Type: ebpf.LRUHash, MaxEntries: 4096},
		"tcp_target":           {Type: ebpf.LRUHash, MaxEntries: 4096},
		"target_cgroup_ids":    {Type: ebpf.Hash, MaxEntries: 4096},
	}}
}

func TestSharedLRUMapsOutgrowPerCPUFreeLists(t *testing.T) {
	spec := sharedLRUSpec()
	raiseSharedLRUMaps(spec, 64)
	for _, name := range sharedLRUMaps {
		if got := spec.Maps[name].MaxEntries; got != 64*lruFreeNodesPerCPU*2 {
			t.Errorf("%s: MaxEntries = %d, want %d", name, got, 64*lruFreeNodesPerCPU*2)
		}
	}
	for _, name := range []string{"tcp_target", "target_cgroup_ids"} {
		if got := spec.Maps[name].MaxEntries; got != 4096 {
			t.Errorf("%s must keep its size, got %d", name, got)
		}
	}
}

func TestSharedLRUMapsNeverShrink(t *testing.T) {
	for _, cpus := range []int{-1, 0, 1, 8} {
		spec := sharedLRUSpec()
		raiseSharedLRUMaps(spec, cpus)
		for _, name := range sharedLRUMaps {
			if got := spec.Maps[name].MaxEntries; got != 4096 {
				t.Errorf("cpus=%d %s: MaxEntries = %d, want 4096", cpus, name, got)
			}
		}
	}
}

func TestSharedLRUMapsSkipNonLRUAndMissingMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"start_times": {Type: ebpf.Hash, MaxEntries: 4096},
	}}
	raiseSharedLRUMaps(spec, 256)
	if got := spec.Maps["start_times"].MaxEntries; got != 4096 {
		t.Errorf("a non-LRU start_times must keep its size, got %d", got)
	}
}
