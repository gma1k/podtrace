package tracer

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/sysfs"
)

func swapCgroupNamespaceRoot(t *testing.T, root string, ok bool) {
	t.Helper()
	orig := cgroupNamespaceRoot
	cgroupNamespaceRoot = func() (string, bool) { return root, ok }
	t.Cleanup(func() { cgroupNamespaceRoot = orig })
}

func TestAPathPrintedFromAPrivateCgroupNamespaceResolvesOnTheHost(t *testing.T) {
	root := fakeProcCgroup(t, "4244", "0::/../../../burstable/pod-b/ctr\n")
	swapCgroupNamespaceRoot(t, "kubepods/besteffort/pod-agent/agent", true)
	dir := filepath.Join(root, "kubepods", "burstable", "pod-b", "ctr")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	want, err := getCgroupIDFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}

	got, ok := procCgroupID(4244)
	if !ok || got != want {
		t.Fatalf("procCgroupID = %d, %v; want %d. An agent in a private cgroup namespace sees every "+
			"other pod's cgroup as a path climbing out of its own; skipping those turns the pid reuse "+
			"guard off for every event", got, ok, want)
	}
}

func TestThePidReuseGuardRefusesAPidNowInAnotherCgroupSeenFromAPrivateNamespace(t *testing.T) {
	root := fakeProcCgroup(t, "4245", "0::/../other-pod/ctr\n")
	swapCgroupNamespaceRoot(t, "kubepods/pod-agent/agent", true)
	if err := os.MkdirAll(filepath.Join(root, "kubepods", "pod-agent", "other-pod", "ctr"), 0o750); err != nil {
		t.Fatal(err)
	}

	if pidInEventCgroup(&events.Event{PID: 4245, CgroupID: 1}) {
		t.Fatal("a pid that now belongs to another cgroup was allowed to name the event")
	}
}

func TestHostCgroupPath(t *testing.T) {
	swapCgroupNamespaceRoot(t, "a/b", true)
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"/x/y", "/x/y", true},
		{"/", "/", true},
		{"/../c", "/a/c", true},
		{"/../../c/d", "/c/d", true},
		{"/../../../../c", "/c", true},
		{"/x/../y", "", false},
		{"/../x/..", "", false},
		{"/x..y", "/x..y", true},
	}
	for _, c := range cases {
		got, ok := hostCgroupPath(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("hostCgroupPath(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestAClimbingPathIsUnverifiableWithoutTheNamespaceRoot(t *testing.T) {
	swapCgroupNamespaceRoot(t, "", false)
	if got, ok := hostCgroupPath("/../c"); ok {
		t.Fatalf("hostCgroupPath = %q with no known namespace root", got)
	}
}

func TestTheNamespaceRootIsTheCgroupListingThisProcess(t *testing.T) {
	root := fakeProcCgroup(t, "4246", "")
	agent := filepath.Join(root, "kubepods", "pod-agent", "agent")
	if err := os.MkdirAll(agent, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agent, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sysfs.ResetForTesting()
	t.Cleanup(sysfs.ResetForTesting)

	got, ok := defaultCgroupNamespaceRoot()
	if !ok || got != "kubepods/pod-agent/agent" {
		t.Fatalf("namespace root = %q, %v", got, ok)
	}
}
