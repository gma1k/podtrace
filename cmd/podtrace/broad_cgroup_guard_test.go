package main

import (
	"reflect"
	"testing"

	"github.com/gma1k/podtrace/internal/kubernetes"
)

func TestCgroupPathNamesContainer(t *testing.T) {
	full := "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name   string
		target kubernetes.ContainerTarget
		want   bool
	}{
		{"full id in path", kubernetes.ContainerTarget{ID: full, CgroupPath: "/sys/fs/cgroup/kubepods/pod1/cri-containerd-" + full + ".scope"}, true},
		{"short id in path", kubernetes.ContainerTarget{ID: full, CgroupPath: "/sys/fs/cgroup/crio-0123456789ab"}, true},
		{"parent slice", kubernetes.ContainerTarget{ID: full, CgroupPath: "/sys/fs/cgroup/kubepods.slice/kubepods-pod1.slice"}, false},
		{"no cgroup path", kubernetes.ContainerTarget{ID: full}, true},
		{"no container id", kubernetes.ContainerTarget{CgroupPath: "/sys/fs/cgroup/anything"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cgroupPathNamesContainer(tt.target); got != tt.want {
				t.Errorf("cgroupPathNamesContainer = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithoutBroadCgroups(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "")
	narrow := &kubernetes.PodInfo{PodName: "ok", Namespace: "shop", ContainerID: "aaa", CgroupPath: "/cg/pod/aaa.scope"}
	broad := &kubernetes.PodInfo{PodName: "broad", Namespace: "shop", ContainerID: "bbb", CgroupPath: "/cg/kubepods.slice"}
	mixed := &kubernetes.PodInfo{
		PodName:   "mixed",
		Namespace: "shop",
		Containers: []kubernetes.ContainerTarget{
			{Name: "app", ID: "ccc", CgroupPath: "/cg/pod/ccc.scope"},
			{Name: "sidecar", ID: "ddd", CgroupPath: "/cg/pod"},
		},
	}

	got := withoutBroadCgroups([]*kubernetes.PodInfo{narrow, broad, mixed})

	if len(got) != 2 || got[0] != narrow || got[1].PodName != "mixed" {
		t.Fatalf("kept %+v, want ok and the narrowed mixed pod", got)
	}
	want := []kubernetes.ContainerTarget{{Name: "app", ID: "ccc", CgroupPath: "/cg/pod/ccc.scope"}}
	if !reflect.DeepEqual(got[1].Containers, want) {
		t.Errorf("mixed containers = %+v, want only app", got[1].Containers)
	}
	if len(mixed.Containers) != 2 {
		t.Error("narrowing mutated the registry's PodInfo")
	}
}

func TestWithoutBroadCgroupsHonoursTheOptOut(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	broad := []*kubernetes.PodInfo{{PodName: "broad", ContainerID: "bbb", CgroupPath: "/cg/kubepods.slice"}}

	if got := withoutBroadCgroups(broad); len(got) != 1 || got[0] != broad[0] {
		t.Errorf("opt-out still filtered: %+v", got)
	}
}

func TestApplyDynamicTargetSnapshotSkipsABroadCgroupPod(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "")
	pod, _ := snapshotPod(t)
	rec := &ownerRecordingTracer{}
	index := newSourcePodIndex([]*kubernetes.PodInfo{pod})
	late := &kubernetes.PodInfo{PodName: "late", Namespace: "shop", ContainerID: "c-late", CgroupPath: t.TempDir()}

	applyDynamicTargetSnapshot(rec, index, []*kubernetes.PodInfo{late})

	if rec.attachArg != "" || rec.setCgroupsArg != nil || rec.owners != nil {
		t.Errorf("tracer was retargeted onto a parent-level cgroup: %+v", rec)
	}
}
