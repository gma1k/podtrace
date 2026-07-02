package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/sysfs"
)

func TestEmitCopyFailAlert(t *testing.T) {
	orig := alerting.GetGlobalManager()
	t.Cleanup(func() { alerting.SetGlobalManager(orig) })

	emitCopyFailAlert(nil)
	emitCopyFailAlert(&events.Event{Type: events.EventAFALG, Target: "skcipher", Bytes: 1000})

	alerting.SetGlobalManager(nil)
	emitCopyFailAlert(&events.Event{Type: events.EventAFALG, Target: "aead", Bytes: 1000})

	mgr, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	alerting.SetGlobalManager(mgr)
	ev := &events.Event{
		Type:        events.EventAFALG,
		Target:      "aead",
		Details:     "gcm(aes)",
		Bytes:       1000,
		ProcessName: "attacker",
		PID:         4242,
	}
	emitCopyFailAlert(ev)
	ev.K8s = &events.K8sMetadata{PodName: "pod-x", Namespace: "ns-y"}
	emitCopyFailAlert(ev)
}

func TestFirstPIDFromCgroupProcs(t *testing.T) {
	base := t.TempDir()
	origBase := config.CgroupBasePath
	config.CgroupBasePath = base
	sysfs.ResetForTesting()
	t.Cleanup(func() {
		config.CgroupBasePath = origBase
		sysfs.ResetForTesting()
	})

	cg := filepath.Join(base, "kubepods.slice", "pod123")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	// Leading blank line + entries; first valid PID wins.
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte("\n4242\n4243\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := firstPIDFromCgroupProcs(cg); got != 4242 {
		t.Errorf("firstPIDFromCgroupProcs = %d, want 4242", got)
	}

	// No cgroup.procs -> 0.
	empty := filepath.Join(base, "kubepods.slice", "podempty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := firstPIDFromCgroupProcs(empty); got != 0 {
		t.Errorf("missing cgroup.procs should give 0, got %d", got)
	}
}