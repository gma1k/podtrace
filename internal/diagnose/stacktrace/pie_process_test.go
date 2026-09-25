package stacktrace

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const pieFixtureSource = `package main

import (
	"fmt"
	"os"
	"reflect"
	"time"
)

//go:noinline
func TargetFunction(n int) int {
	return n * 3
}

func main() {
	fmt.Println(reflect.ValueOf(TargetFunction).Pointer())
	os.Stdout.Sync()
	time.Sleep(60 * time.Second)
}
`

func startPIEProcess(t *testing.T) (pid int, entry uint64) {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(pieFixtureSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module piefix\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "piefix")
	build := exec.Command(goTool, "build", "-buildmode=pie", "-o", bin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build a PIE fixture here: %v\n%s", err, out)
	}

	cmd := exec.Command(bin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read fixture address: %v", err)
	}
	entry, err = strconv.ParseUint(strings.TrimSpace(line), 10, 64)
	if err != nil {
		t.Fatalf("parse fixture address %q: %v", line, err)
	}
	return cmd.Process.Pid, entry
}

func TestAFrameInARunningPIEBinaryIsNamed(t *testing.T) {
	pid, entry := startPIEProcess(t)

	r := NewResolver()
	got := r.Resolve(context.Background(), uint32(pid), entry+1)
	if got != "main.TargetFunction" {
		t.Errorf("Resolve(pid %d, %#x) = %q, want main.TargetFunction.\n\n"+
			"A PIE binary runs at a random base, so its addresses must be translated through "+
			"/proc/<pid>/maps before a symbol lookup. The mappings were matched against the "+
			"host-side path /proc/<pid>/root/<exe>, which maps never names, so translation "+
			"failed and every PIE frame stayed a raw address.", pid, entry+1, got)
	}
}
