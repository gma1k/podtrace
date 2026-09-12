package tracer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/procfs"
)

func fakeProcWithContainer(t *testing.T, pid string, containerID string) {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cgroup := "0::/kubepods.slice/cri-containerd-" + containerID + ".scope\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
		t.Fatalf("write cgroup: %v", err)
	}

	previous := config.ProcBasePath
	config.SetProcBasePath(root)
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetProcBasePath(previous)
		procfs.ResetForTesting()
	})
}

func TestContainerTargetsCarryAResolvedPID(t *testing.T) {
	const id = "containeraaaa"
	fakeProcWithContainer(t, "4242", id)

	tr := &Tracer{filter: filter.NewCgroupFilter()}
	if err := tr.SetContainerIDs([]string{id}); err != nil {
		t.Fatalf("SetContainerIDs: %v", err)
	}

	set, ok := tr.containerUprobes[id]
	if !ok {
		t.Fatalf("no uprobe set recorded for %q", id)
	}
	if len(set.pids) != 1 || set.pids[0] != 4242 {
		t.Errorf("recorded pids = %v, want [4242].\n\n"+
			"Without a seeded pid, pidsForContainer falls back to a single zero whenever "+
			"no attached cgroup path matches the container. The container-id-aware attach "+
			"functions recover from that, but GoTLS, gRPC-Go, rustls, quiche, quiche-rust "+
			"and USDT take a pid and nothing else, so they silently attach nothing.",
			set.pids)
	}
}

func TestAnUnresolvableContainerKeepsTheZeroPIDFallback(t *testing.T) {
	fakeProcWithContainer(t, "4242", "containeraaaa")

	tr := &Tracer{filter: filter.NewCgroupFilter()}
	if err := tr.SetContainerIDs([]string{"containerzzzz"}); err != nil {
		t.Fatalf("SetContainerIDs must not fail when a container has no process yet: %v", err)
	}

	set, ok := tr.containerUprobes["containerzzzz"]
	if !ok {
		t.Fatal("an unresolvable container lost its uprobe set entirely")
	}
	if len(set.pids) != 1 || set.pids[0] != 0 {
		t.Errorf("recorded pids = %v, want [0].\n\npidsForContainer deliberately returns "+
			"a single zero rather than an empty slice, because the container-id-aware "+
			"attach functions resolve the container themselves from a zero pid. Returning "+
			"nothing would make attachContainerGroupUprobes bail before any of them ran.",
			set.pids)
	}
}

func TestEachContainerGetsItsOwnPID(t *testing.T) {
	root := t.TempDir()
	for pid, id := range map[string]string{"11": "containeraaaa", "22": "containerbbbb"} {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		cgroup := "0::/kubepods.slice/cri-containerd-" + id + ".scope\n"
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatalf("write cgroup: %v", err)
		}
	}
	previous := config.ProcBasePath
	config.SetProcBasePath(root)
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetProcBasePath(previous)
		procfs.ResetForTesting()
	})

	tr := &Tracer{filter: filter.NewCgroupFilter()}
	if err := tr.SetContainerIDs([]string{"containeraaaa", "containerbbbb"}); err != nil {
		t.Fatalf("SetContainerIDs: %v", err)
	}

	want := map[string]uint32{"containeraaaa": 11, "containerbbbb": 22}
	for id, pid := range want {
		set, ok := tr.containerUprobes[id]
		if !ok {
			t.Errorf("no uprobe set for %q", id)
			continue
		}
		if len(set.pids) != 1 || set.pids[0] != pid {
			t.Errorf("%q recorded pids %v, want [%d]; one container's uprobes attached "+
				"to another's process would report the wrong workload's traffic",
				id, set.pids, pid)
		}
	}
}
