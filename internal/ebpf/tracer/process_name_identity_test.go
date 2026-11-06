package tracer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/procfs"
)

func fakeProcess(t *testing.T, base string, pid uint32, name string, startTicks uint64) {
	t.Helper()
	dir := filepath.Join(base, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0", pid, name, startTicks)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte("/usr/bin/"+name+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func nameTestTracer(t *testing.T) (*Tracer, string) {
	t.Helper()
	base := t.TempDir()
	prev := config.ProcBasePath
	config.SetProcBasePath(base)
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetProcBasePath(prev)
		procfs.ResetForTesting()
	})
	c := cache.NewLRUCache(64, time.Hour)
	t.Cleanup(c.Close)
	return &Tracer{processNameCache: c}, base
}

func TestAReusedPIDIsNamedAfterItsNewProcess(t *testing.T) {
	tr, base := nameTestTracer(t)
	fakeProcess(t, base, 4242, "tenant-a-worker", 100)
	if got := tr.getProcessNameQuick(4242); got != "tenant-a-worker" {
		t.Fatalf("first name = %q", got)
	}

	fakeProcess(t, base, 4242, "tenant-b-api", 900)
	if got := tr.getProcessNameQuick(4242); got != "tenant-b-api" {
		t.Fatalf("name = %q; a pid handed to a new process kept its predecessor's name", got)
	}
}

func TestTheSameProcessIsNamedFromTheCache(t *testing.T) {
	tr, base := nameTestTracer(t)
	fakeProcess(t, base, 4242, "worker", 100)
	tr.getProcessNameQuick(4242)

	if err := os.WriteFile(filepath.Join(base, "4242", "cmdline"), []byte("renamed\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := tr.getProcessNameQuick(4242); got != "worker" {
		t.Fatalf("name = %q, want the cached name for the same process", got)
	}
}

func TestAnExitedProcessIsNamedOnlyFromARecentEntry(t *testing.T) {
	tr, base := nameTestTracer(t)
	fakeProcess(t, base, 4242, "short-lived", 100)
	tr.getProcessNameQuick(4242)
	if err := os.RemoveAll(filepath.Join(base, "4242")); err != nil {
		t.Fatal(err)
	}
	if got := tr.getProcessNameQuick(4242); got != "short-lived" {
		t.Fatalf("name = %q; a process that just exited should keep its recent name", got)
	}

	prev := config.PIDCacheTTLSeconds
	config.PIDCacheTTLSeconds = 0
	t.Cleanup(func() { config.PIDCacheTTLSeconds = prev })
	if got := tr.getProcessNameQuick(4242); got != "" {
		t.Fatalf("name = %q; an entry older than the pid TTL may belong to any earlier holder of the pid", got)
	}
}
