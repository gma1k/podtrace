//go:build bpf_loadtest && linux

package tracer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const cpuWorkerEnv = "PODTRACE_CPU_WORKER"

type cpuQuotaEntry struct {
	QuotaMicros  uint64
	PeriodMicros uint64
}

type cpuAlertKey struct {
	CgroupID     uint64
	ResourceType uint32
	_            uint32
}

func TestKernelCPUWorker(t *testing.T) {
	if os.Getenv(cpuWorkerEnv) == "" {
		t.Skip("only runs as the child of the CPU quota kernel tests")
	}
	fmt.Println("ready")
	var line [8]byte
	_, _ = os.Stdin.Read(line[:])
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		spinUntil := time.Now().Add(20 * time.Millisecond)
		for time.Now().Before(spinUntil) {
		}
		time.Sleep(time.Millisecond)
	}
	fmt.Println("done")
	syscall.Exit(0)
}

func schedSwitchOnly(t *testing.T) *ebpf.Collection {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(compiledObjectPath(t))
	if err != nil {
		t.Skipf("BPF object not built: %v", err)
	}
	for name := range spec.Programs {
		if name != "tracepoint_sched_switch" {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skipf("cannot load BPF here (needs root): %v", err)
	}
	t.Cleanup(coll.Close)
	tp, err := link.Tracepoint("sched", "sched_switch", coll.Programs["tracepoint_sched_switch"], nil)
	if err != nil {
		t.Fatalf("attach sched_switch: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	return coll
}

func makeCgroups(t *testing.T, path ...string) []string {
	t.Helper()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("cgroup v2 not mounted at /sys/fs/cgroup")
	}
	dirs := make([]string, 0, len(path))
	dir := "/sys/fs/cgroup"
	for _, p := range path {
		dir = filepath.Join(dir, p)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Skipf("cannot create cgroups here (needs root): %v", err)
		}
		dirs = append(dirs, dir)
	}
	t.Cleanup(func() {
		for i := len(dirs) - 1; i >= 0; i-- {
			_ = os.Remove(dirs[i])
		}
	})
	return dirs
}

func cgroupID(t *testing.T, path string) uint64 {
	t.Helper()
	id, err := getCgroupIDFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestKernelContainerCPUIsChargedToThePodQuota(t *testing.T) {
	for name, layout := range map[string][]string{
		"container under pod":             {"ctr"},
		"nested container under pod":      {"ctr", "container"},
		"quota on the task cgroup itself": nil,
	} {
		t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
			coll := schedSwitchOnly(t)
			dirs := makeCgroups(t, append([]string{fmt.Sprintf("podtrace-cpu-pod-%d", os.Getpid())}, layout...)...)
			owner, leaf := dirs[0], dirs[len(dirs)-1]
			ownerID, leafID := cgroupID(t, owner), cgroupID(t, leaf)

			if err := coll.Maps["target_cgroup_ids"].Put(leafID, uint8(1)); err != nil {
				t.Fatal(err)
			}
			if err := coll.Maps["cgroup_cpu_quota"].Put(ownerID, cpuQuotaEntry{QuotaMicros: 10_000, PeriodMicros: 100_000}); err != nil {
				t.Fatal(err)
			}

			runInCgroup(t, leaf, "TestKernelCPUWorker", cpuWorkerEnv+"=1")

			var level uint32
			if err := coll.Maps["cgroup_alerts"].Lookup(cpuAlertKey{CgroupID: ownerID}, &level); err != nil {
				t.Fatalf("no CPU alert level for the quota's cgroup: %v", err)
			}
			if level != 3 {
				t.Fatalf("alert level = %d, want emergency for a worker using ~10x a 0.1 CPU quota", level)
			}
			if ownerID != leafID {
				if err := coll.Maps["cgroup_alerts"].Lookup(cpuAlertKey{CgroupID: leafID}, &level); err == nil {
					t.Fatal("the alert was keyed by the task's cgroup instead of the one holding the quota")
				}
			}
		})
	}
}

func TestKernelCPUWithoutAQuotaAnywhereOpensNoWindow(t *testing.T) {
	coll := schedSwitchOnly(t)
	dirs := makeCgroups(t, fmt.Sprintf("podtrace-cpu-noquota-%d", os.Getpid()), "ctr")
	leafID := cgroupID(t, dirs[1])
	if err := coll.Maps["target_cgroup_ids"].Put(leafID, uint8(1)); err != nil {
		t.Fatal(err)
	}

	runInCgroup(t, dirs[1], "TestKernelCPUWorker", cpuWorkerEnv+"=1")

	var window [2]uint64
	for _, id := range []uint64{leafID, cgroupID(t, dirs[0])} {
		if err := coll.Maps["cgroup_cpu_window"].Lookup(id, &window); err == nil {
			t.Fatalf("cgroup %d has a CPU window although no cgroup has a quota", id)
		}
	}
}
