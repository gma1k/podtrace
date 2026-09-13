package tracer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoBTFFileNamedResolvesToHostBTF(t *testing.T) {
	spec, err := kernelTypesFromFile("")
	if err != nil {
		t.Fatalf("kernelTypesFromFile(\"\"): %v", err)
	}
	if spec != nil {
		t.Error("a spec was returned with no file named; the collection must be left to " +
			"resolve host BTF itself")
	}
}

func TestANamedBTFFileThatIsMissingIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.btf")

	spec, err := kernelTypesFromFile(path)
	if err == nil {
		t.Fatal("a missing blob resolved without error.\n\nbtfMode=file is only set on a " +
			"node whose kernel carries no BTF, so falling back leaves the agent relocating " +
			"against stub types while reporting healthy -- exactly what btfMode=embedded did.")
	}
	if spec != nil {
		t.Error("a spec was returned alongside the error")
	}
	if !strings.Contains(err.Error(), "PODTRACE_BTF_FILE") || !strings.Contains(err.Error(), path) {
		t.Errorf("error %q names neither the variable nor the path", err)
	}
}

func TestANamedBTFFileThatIsNotBTFIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.btf")
	if err := os.WriteFile(path, []byte("this is not BTF"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := kernelTypesFromFile(path); err == nil {
		t.Fatal("an unparseable blob resolved without error; a truncated or wrong-format " +
			"file must be reported, not stepped over")
	}
}

func TestARealBTFBlobResolves(t *testing.T) {
	const hostBTF = "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(hostBTF); err != nil {
		t.Skipf("no host BTF to read: %v", err)
	}

	spec, err := kernelTypesFromFile(hostBTF)
	if err != nil {
		t.Fatalf("kernelTypesFromFile(%s): %v", hostBTF, err)
	}
	if spec == nil {
		t.Fatal("nil spec for a readable BTF blob")
	}
	if _, err := spec.AnyTypeByName("task_struct"); err != nil {
		t.Errorf("task_struct absent from the resolved spec: %v", err)
	}
}
