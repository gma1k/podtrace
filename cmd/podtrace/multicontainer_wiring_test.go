package main

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

func TestTargetAttachSets_FansOutAllContainers(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	infos := []*kubernetes.PodInfo{{
		PodName: "web", Namespace: "default",
		Containers: []kubernetes.ContainerTarget{
			{Name: "app", ID: "aaa", CgroupPath: d1},
			{Name: "sidecar", ID: "bbb", CgroupPath: d2},
		},
		ContainerID: "aaa", CgroupPath: d1, ContainerName: "app",
	}}
	paths, ids := targetAttachSets(infos)
	if len(paths) != 2 || len(ids) != 2 {
		t.Fatalf("attach sets = %d paths / %d ids, want 2/2", len(paths), len(ids))
	}
	if ids[0] != "aaa" || ids[1] != "bbb" {
		t.Errorf("container IDs = %v, want [aaa bbb]", ids)
	}
}

func TestTargetAttachSets_LegacySingularFallback(t *testing.T) {
	infos := []*kubernetes.PodInfo{{
		PodName: "old", Namespace: "ns",
		ContainerID: "ccc", CgroupPath: "/sys/fs/cgroup/x", ContainerName: "app",
	}}
	paths, ids := targetAttachSets(infos)
	if len(paths) != 1 || len(ids) != 1 || ids[0] != "ccc" {
		t.Fatalf("legacy fallback = %v / %v, want single entry from singular fields", paths, ids)
	}
}

func TestSourcePodIndex_PerContainerAttribution(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	info := &kubernetes.PodInfo{
		PodName: "web", Namespace: "default",
		Containers: []kubernetes.ContainerTarget{
			{Name: "app", ID: "aaa", CgroupPath: d1},
			{Name: "sidecar", ID: "bbb", CgroupPath: d2},
		},
		ContainerID: "aaa", CgroupPath: d1, ContainerName: "app",
	}
	idx := newSourcePodIndex([]*kubernetes.PodInfo{info})

	cg1, err := cgroupIDFromPath(d1)
	if err != nil {
		t.Fatal(err)
	}
	cg2, err := cgroupIDFromPath(d2)
	if err != nil {
		t.Fatal(err)
	}

	if got := idx.Resolve(&events.Event{CgroupID: cg1}); got == nil || got.ContainerName != "app" {
		t.Errorf("cgroup1 attribution = %+v, want container app", got)
	}
	if got := idx.Resolve(&events.Event{CgroupID: cg2}); got == nil || got.ContainerName != "sidecar" {
		t.Errorf("cgroup2 attribution = %+v, want container sidecar", got)
	}
}
