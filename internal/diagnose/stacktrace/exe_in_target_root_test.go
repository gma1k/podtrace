package stacktrace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func procTreeWithExe(t *testing.T, pid string, exeRelPath string) string {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, pid, "root", exeRelPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	orig := config.ProcBasePath
	config.SetProcBasePath(root)
	t.Cleanup(func() { config.SetProcBasePath(orig) })
	return full
}

func TestExeIsReachedThroughTheTargetsRootfs(t *testing.T) {
	want := procTreeWithExe(t, "4242", "app/server")

	got, err := exeInTargetRoot(4242, "/app/server")
	if err != nil {
		t.Fatalf("exeInTargetRoot: %v", err)
	}
	if got != want {
		t.Errorf("path = %q, want %q.\n\n/proc/<pid>/exe resolves inside the target's "+
			"mount namespace, so a containerised binary is not at that path in the "+
			"tracer's namespace and every frame falls back to a raw address.", got, want)
	}
}

func TestAnExeSharedWithTheTracerStillResolves(t *testing.T) {
	root := t.TempDir()
	orig := config.ProcBasePath
	config.SetProcBasePath(root)
	t.Cleanup(func() { config.SetProcBasePath(orig) })

	shared := filepath.Join(root, "local-binary")
	if err := os.WriteFile(shared, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := exeInTargetRoot(1, shared)
	if err != nil {
		t.Fatalf("exeInTargetRoot: %v", err)
	}
	if got != shared {
		t.Errorf("path = %q, want the bare path %q; a local run shares the namespace "+
			"and has no /proc/<pid>/root indirection", got, shared)
	}
}

func TestAnUnreachableExeIsReportedRatherThanGuessed(t *testing.T) {
	root := t.TempDir()
	orig := config.ProcBasePath
	config.SetProcBasePath(root)
	t.Cleanup(func() { config.SetProcBasePath(orig) })

	if _, err := exeInTargetRoot(99, "/gone/binary"); err == nil {
		t.Error("a missing executable resolved without error; addr2line would then be " +
			"handed a path that does not exist")
	}
}
