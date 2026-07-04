package tracer

import (
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf/filter"
)

func TestIdleDeny(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}

	if tr.idleDeny() {
		t.Fatal("permissive default: idleDeny must be false without the mode")
	}

	tr.SetDenyWhenNoTargets(true)
	if !tr.idleDeny() {
		t.Fatal("deny mode with zero targets must report idleDeny")
	}

	tr.storeCgroupIDs(map[uint64]struct{}{42: {}})
	if tr.idleDeny() {
		t.Fatal("kernel-side cgroup ids present: idleDeny must be false")
	}
	tr.storeCgroupIDs(map[uint64]struct{}{})

	tr.filter.SetCgroupPaths([]string{"/sys/fs/cgroup/kubepods/pod-a"})
	if tr.idleDeny() {
		t.Fatal("userspace filter paths present: idleDeny must be false")
	}
	tr.filter.SetCgroupPaths(nil)

	if !tr.idleDeny() {
		t.Fatal("targets cleared again: idleDeny must be true")
	}

	tr.SetDenyWhenNoTargets(false)
	if tr.idleDeny() {
		t.Fatal("mode disabled: idleDeny must be false")
	}
}

func TestSyncTargetCgroupMapWithoutCollection(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	tr.SetDenyWhenNoTargets(true)
	if err := tr.syncTargetCgroupMap(); err != nil {
		t.Fatalf("syncTargetCgroupMap without collection errored: %v", err)
	}
}
