package kubernetes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestValidCgroupFlagValue(t *testing.T) {
	origBase := config.CgroupBasePath
	base := t.TempDir()
	config.SetCgroupBasePath(base)
	defer config.SetCgroupBasePath(origBase)

	cases := []struct {
		v    string
		want bool
	}{
		{"", false},
		{"kubepods", true},
		{"kubepods.slice", true},
		{"../../../..", false},
		{"foo/../bar", false},
		{"/proc", false},
		{"/", false},
		{filepath.Join(base, "kubepods"), true},
	}
	for _, c := range cases {
		if got := validCgroupFlagValue(c.v); got != c.want {
			t.Errorf("validCgroupFlagValue(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestCgroupRootCandidates_RejectsPoisonedKubeletRoot(t *testing.T) {
	_ = detectKubeletCgroupParent()

	origBase := config.CgroupBasePath
	base := t.TempDir()
	config.SetCgroupBasePath(base)
	defer config.SetCgroupBasePath(origBase)

	origKCP := kubeletCgroupParent
	defer func() { kubeletCgroupParent = origKCP }()

	for _, poison := range []string{"../../../..", "/proc", "/", "../../../../../.."} {
		kubeletCgroupParent = poison
		for _, c := range cgroupRootCandidates() {
			if c == "/" || c == "/proc" || !strings.HasPrefix(c, base) {
				t.Errorf("poisoned kubelet root %q produced out-of-base walk root %q", poison, c)
			}
		}
	}
}

func TestReadKubeletCgroupFlag_SkipsSpoofedInvalidValue(t *testing.T) {
	procDir := t.TempDir()
	origProc := config.ProcBasePath
	config.SetProcBasePath(procDir)
	defer config.SetProcBasePath(origProc)

	origBase := config.CgroupBasePath
	config.SetCgroupBasePath(t.TempDir())
	defer config.SetCgroupBasePath(origBase)

	writeFakeKubelet(t, procDir, "10001", "kubelet\x00--cgroup-root\x00../../../..\x00")
	writeFakeKubelet(t, procDir, "2345", "kubelet\x00--cgroup-root\x00kubepods\x00")

	if got := readKubeletCgroupFlag(); got != "kubepods" {
		t.Fatalf("readKubeletCgroupFlag()=%q, want %q (a spoofed first-match with an escaping value must be skipped)", got, "kubepods")
	}
}

func TestFindCgroupPathV1_RequiresDirWithCgroupProcs(t *testing.T) {
	origBase := config.CgroupBasePath
	base := t.TempDir()
	config.SetCgroupBasePath(base)
	defer config.SetCgroupBasePath(origBase)

	kubepods := filepath.Join(base, "kubepods.slice")
	if err := os.MkdirAll(kubepods, 0o755); err != nil {
		t.Fatal(err)
	}

	cid := "abcdef1234567890abcdef12"
	if err := os.WriteFile(filepath.Join(kubepods, "pod_"+cid+".txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(kubepods, "nodir_"+cid), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := findCgroupPathV1(cid); err == nil {
		t.Fatal("v1 must not match a file, nor a dir lacking cgroup.procs")
	}

	leaf := filepath.Join(kubepods, "pod_"+cid)
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupPathV1(cid)
	if err != nil || got != leaf {
		t.Fatalf("v1 should match the leaf dir with cgroup.procs: got %q err %v", got, err)
	}
}

func TestReadKubeletCgroupFlag_SkipsKubeletWithoutCmdline(t *testing.T) {
	procDir := t.TempDir()
	origProc := config.ProcBasePath
	config.SetProcBasePath(procDir)
	defer config.SetProcBasePath(origProc)

	d := filepath.Join(procDir, "4242")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "comm"), []byte("kubelet\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := readKubeletCgroupFlag(); got != "" {
		t.Fatalf("readKubeletCgroupFlag()=%q, want empty (kubelet with unreadable cmdline is skipped)", got)
	}
}

func writeFakeKubelet(t *testing.T, procDir, pid, cmdline string) {
	t.Helper()
	d := filepath.Join(procDir, pid)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "comm"), []byte("kubelet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "cmdline"), []byte(cmdline), 0o644); err != nil {
		t.Fatal(err)
	}
}
