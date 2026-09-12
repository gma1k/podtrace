package probes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/procfs"
)

func procWithCgroups(t *testing.T, byPID map[string]string) {
	t.Helper()

	root := t.TempDir()
	for pid, cgroup := range byPID {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatalf("write cgroup: %v", err)
		}
	}

	orig := config.ProcBasePath
	config.SetProcBasePath(root)
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetProcBasePath(orig)
		procfs.ResetForTesting()
	})
}

func TestFindContainerProcessResolvesTheContainersPID(t *testing.T) {
	procWithCgroups(t, map[string]string{
		"7": "0::/kubepods.slice/cri-containerd-containeraaaa.scope\n",
	})

	if got := FindContainerProcess("containeraaaa"); got != 7 {
		t.Errorf("FindContainerProcess = %d, want 7", got)
	}
}

func TestFindContainerProcessReturnsZeroForAnUnknownContainer(t *testing.T) {
	procWithCgroups(t, map[string]string{
		"7": "0::/kubepods.slice/cri-containerd-containeraaaa.scope\n",
	})

	if got := FindContainerProcess("containerzzzz"); got != 0 {
		t.Errorf("FindContainerProcess = %d, want 0.\n\nThe caller seeds this into a "+
			"ContainerProbeTarget; inventing a pid would attach a container's uprobes to "+
			"a process that is not it.", got)
	}
}

func TestFindContainerProcessIgnoresNonNumericProcEntries(t *testing.T) {
	procWithCgroups(t, map[string]string{
		"self":   "0::/kubepods.slice/cri-containerd-containeraaaa.scope\n",
		"sys":    "0::/kubepods.slice/cri-containerd-containeraaaa.scope\n",
		"000009": "0::/kubepods.slice/cri-containerd-containeraaaa.scope\n",
	})

	if got := FindContainerProcess("containeraaaa"); got != 9 {
		t.Errorf("FindContainerProcess = %d, want 9; /proc holds entries like self and "+
			"sys beside the pids, and parsing one as a pid yields a target that never "+
			"resolves", got)
	}
}
