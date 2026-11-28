package containerid

import (
	"strings"
	"testing"
)

const (
	full    = "0123456789ab" + "cdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
	sibling = "0123456789ab" + "ffff0123456789abcdef0123456789abcdef0123456789abcdef0123"
)

func TestInPathMatchesTheContainersOwnCgroup(t *testing.T) {
	for _, p := range []string{
		"/sys/fs/cgroup/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + full + ".scope",
		"/sys/fs/cgroup/docker/" + full,
		"0::/kubepods/burstable/pod1/crio-" + full + ".scope\n",
		"/sys/fs/cgroup/system.slice/docker-0123456789ab.scope",
		full,
	} {
		if !InPath(p, full) {
			t.Errorf("InPath(%q) = false, want true", p)
		}
	}
}

func TestInPathNeverMatchesAnotherContainerSharingTheShortPrefix(t *testing.T) {
	for _, p := range []string{
		"/sys/fs/cgroup/kubepods.slice/cri-containerd-" + sibling + ".scope",
		"/sys/fs/cgroup/docker/" + sibling,
		"/sys/fs/cgroup/kubepods/f" + full,
	} {
		if InPath(p, full) {
			t.Errorf("InPath(%q) = true for a different container", p)
		}
	}
}

func TestInPathKeepsAnAbbreviatedIDAsAPrefix(t *testing.T) {
	if !InPath("/sys/fs/cgroup/docker/"+full, full[:16]) {
		t.Error("an abbreviated id given by the caller no longer finds its container")
	}
	if InPath("/sys/fs/cgroup/docker/"+full, "") {
		t.Error("an empty id matched")
	}
	if InPath("/a/b", strings.Repeat("f", 64)) {
		t.Error("an absent id matched")
	}
}
