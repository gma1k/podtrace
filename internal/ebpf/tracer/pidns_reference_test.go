package tracer

import (
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestAStaleBPFObjectWithoutTheMapIsReported(t *testing.T) {
	got := populatePidNamespace(&ebpf.Collection{})

	if got == "" {
		t.Fatal("a collection with no pidns_ref map reported success.\n\nBPF then falls " +
			"back to the init-namespace tgid, so on a nested node every per-pid map lookup " +
			"misses and the probes that depend on them report nothing, which is " +
			"indistinguishable from a workload that had no activity.")
	}
	if got != "BPF object has no pidns_ref map" {
		t.Errorf("reason = %q, want it to name the missing map", got)
	}
}

func TestTheNodeNamespaceIsPreferredOverTheAgentsOwn(t *testing.T) {
	path, st, err := pidNamespaceStat("/proc")
	if err != nil {
		t.Fatalf("pidNamespaceStat(/proc): %v", err)
	}
	if path != "/proc/1/ns/pid" {
		t.Errorf("path = %q, want the init namespace under the given /proc", path)
	}
	if st.Ino == 0 {
		t.Error("inode 0; BPF treats that as no translation configured")
	}
}

func TestAnUnmountedHostProcFallsBackToTheAgentsOwnNamespace(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "not-mounted")

	path, st, err := pidNamespaceStat(absent)
	if err != nil {
		t.Fatalf("fallback failed: %v.\n\nWithout /host/proc the agent must still record "+
			"its own namespace rather than record nothing", err)
	}
	if path != filepath.Join(absent, "1", "ns", "pid") {
		t.Errorf("path = %q, want the attempted host path for the log", path)
	}
	if st.Ino == 0 {
		t.Error("inode 0 from the fallback; BPF treats that as no translation configured")
	}
}
