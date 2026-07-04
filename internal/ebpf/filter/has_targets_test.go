package filter

import "testing"

func TestHasTargets(t *testing.T) {
	f := NewCgroupFilter()
	if f.HasTargets() {
		t.Fatal("fresh filter must report no targets")
	}

	f.SetCgroupPaths([]string{"/sys/fs/cgroup/kubepods/pod-a"})
	if !f.HasTargets() {
		t.Fatal("filter with a configured path must report targets")
	}

	f.SetCgroupPaths(nil)
	if f.HasTargets() {
		t.Fatal("cleared filter must report no targets")
	}

	f.SetCgroupPath("/sys/fs/cgroup/kubepods/pod-b")
	if !f.HasTargets() {
		t.Fatal("filter with a single legacy path must report targets")
	}
}
