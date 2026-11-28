package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

const (
	prefixTarget  = "0123456789abffff0123456789abcdef0123456789abcdef0123456789abcdef"
	prefixSibling = "0123456789ab00000123456789abcdef0123456789abcdef0123456789abcdef"
)

func containerScope(t *testing.T, base, id string) string {
	t.Helper()
	scope := filepath.Join(base, "kubepods.slice", "kubepods-pod1.slice", "cri-containerd-"+id+".scope")
	if err := os.MkdirAll(scope, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestFindCgroupPathV2NeverResolvesAContainerSharingTheShortPrefix(t *testing.T) {
	origBase := config.CgroupBasePath
	base := t.TempDir()
	config.SetCgroupBasePath(base)
	t.Cleanup(func() { config.SetCgroupBasePath(origBase) })

	containerScope(t, base, prefixSibling)
	if got, err := findCgroupPathV2(prefixTarget); err == nil {
		t.Fatalf("resolved %q, another container whose ID shares the first 12 characters", got)
	}
	want := containerScope(t, base, prefixTarget)
	if got, err := findCgroupPathV2(prefixTarget); err != nil || got != want {
		t.Fatalf("findCgroupPathV2 = %q, %v; want %q", got, err, want)
	}
}

func TestFindCgroupPathFromProcSkipsAProcessOfAContainerSharingTheShortPrefix(t *testing.T) {
	base := t.TempDir()
	origProc, origCgroup := config.ProcBasePath, config.CgroupBasePath
	config.SetProcBasePath(base)
	config.SetCgroupBasePath(base)
	t.Cleanup(func() {
		config.SetProcBasePath(origProc)
		config.SetCgroupBasePath(origCgroup)
	})
	containerScope(t, base, prefixSibling)
	if err := os.MkdirAll(filepath.Join(base, "4242"), 0o750); err != nil {
		t.Fatal(err)
	}
	line := "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + prefixSibling + ".scope\n"
	if err := os.WriteFile(filepath.Join(base, "4242", "cgroup"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := findCgroupPathFromProc(prefixTarget); err == nil {
		t.Fatalf("resolved %q from a process of another container", got)
	}
}

func TestACgroupLineNamesOnlyItsOwnContainer(t *testing.T) {
	line := "/kubepods.slice/cri-containerd-" + prefixSibling + ".scope"
	if cgroupLineNamesContainer(line, prefixTarget) {
		t.Error("a cgroup line of a container sharing the short prefix was taken for the target")
	}
	if !cgroupLineNamesContainer("/kubepods.slice/cri-containerd-"+prefixTarget+".scope", prefixTarget) {
		t.Error("the target's own cgroup line was refused")
	}
}
