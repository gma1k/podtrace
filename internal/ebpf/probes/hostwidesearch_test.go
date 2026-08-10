package probes

import (
	"strings"
	"testing"
)

func TestHostWideLibrarySearch(t *testing.T) {
	cases := []struct {
		containerID string
		pid         uint32
		want        bool
	}{
		{"", 0, true},
		{"abc123", 0, false},
		{"", 4242, false},
		{"abc123", 4242, false},
	}
	for _, c := range cases {
		if got := hostWideLibrarySearch(c.containerID, c.pid); got != c.want {
			t.Errorf("hostWideLibrarySearch(%q, %d) = %v, want %v", c.containerID, c.pid, got, c.want)
		}
	}
}

func assertAllUnder(t *testing.T, root string, paths []string) {
	t.Helper()
	for _, p := range paths {
		if !strings.HasPrefix(p, root) {
			t.Errorf("resolved %q, which is outside the trace target at %q", p, root)
		}
	}
}

func TestFindTLSLibsWithPID_TargetedRunStaysInsideTarget(t *testing.T) {
	f := newFakeProc(t, 42001)

	lib := f.writeContainerFile(t, "/usr/lib/x86_64-linux-gnu/libssl.so.3", "POD LIBSSL")
	f.writeMaps(t, "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /usr/lib/x86_64-linux-gnu/libssl.so.3\n")

	got := findTLSLibsWithPID("", f.pid)

	assertAllUnder(t, f.procBase, got)
	if len(got) != 1 || got[0] != lib {
		t.Fatalf("got %v, want [%s]", got, lib)
	}
}

func TestFindTLSLibsWithPID_TargetedRunWithNoLibraryReturnsNothing(t *testing.T) {
	f := newFakeProc(t, 42002)
	f.writeMaps(t, "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /usr/bin/app\n")

	if got := findTLSLibsWithPID("", f.pid); len(got) != 0 {
		t.Fatalf("got %v, want none: the target has no TLS library and node-wide libraries must not be attached", got)
	}
}

func TestFindDBLibsWithPID_TargetedRunStaysInsideTarget(t *testing.T) {
	f := newFakeProc(t, 42003)

	lib := f.writeContainerFile(t, "/usr/lib/x86_64-linux-gnu/libpq.so.5", "POD LIBPQ")
	f.writeMaps(t, "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /usr/lib/x86_64-linux-gnu/libpq.so.5\n")

	got := findDBLibsWithPID("", f.pid, []string{"libpq.so.5"})

	assertAllUnder(t, f.procBase, got)
	if len(got) != 1 || got[0] != lib {
		t.Fatalf("got %v, want [%s]", got, lib)
	}
}

func TestFindDBLibsWithPID_TargetedRunWithNoLibraryReturnsNothing(t *testing.T) {
	f := newFakeProc(t, 42004)
	f.writeMaps(t, "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /usr/bin/app\n")

	if got := findDBLibsWithPID("", f.pid, []string{"libpq.so.5"}); len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}

func TestFindLibcPathWithPID_TargetedRunStaysInsideTarget(t *testing.T) {
	f := newFakeProc(t, 42005)

	lib := f.writeContainerFile(t, "/lib/x86_64-linux-gnu/libc.so.6", "POD LIBC")
	f.writeMaps(t, "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6\n")

	if got := FindLibcPathWithPID("", f.pid); got != lib {
		t.Fatalf("got %q, want %q", got, lib)
	}
}

func TestFindLibcPathWithPID_TargetedRunWithNoLibcReturnsNothing(t *testing.T) {
	f := newFakeProc(t, 42006)
	f.writeMaps(t, "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /usr/bin/app\n")

	if got := FindLibcPathWithPID("", f.pid); got != "" {
		t.Fatalf("got %q, want empty: the target has no libc and the node's must not be attached", got)
	}
}

func TestFindLibcPathWithPID_UntargetedRunMaySearchHost(t *testing.T) {
	if got := FindLibcPathWithPID("", 0); got != "" && !strings.HasPrefix(got, "/") {
		t.Fatalf("got %q, want an absolute host path or empty", got)
	}
}

func TestFindTLSLibsInContainer_EmptyIDMatchesNothing(t *testing.T) {
	if got := findTLSLibsInContainer("", tlsLibPatterns); len(got) != 0 {
		t.Fatalf("got %d paths for an empty container ID; an empty ID substring-matches every container rootfs on the node", len(got))
	}
}

func TestFindDBLibsInContainer_EmptyIDMatchesNothing(t *testing.T) {
	if got := findDBLibsInContainer("", []string{"libpq.so.5"}); len(got) != 0 {
		t.Fatalf("got %d paths for an empty container ID", len(got))
	}
}

func TestFindLibcInContainer_EmptyIDMatchesNoRootfs(t *testing.T) {
	if got := findLibcInContainer(""); got != "" {
		t.Fatalf("got %q for an empty container ID", got)
	}
}
