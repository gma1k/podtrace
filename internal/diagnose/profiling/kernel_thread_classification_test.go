package profiling

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/events"
)

func emptyProc(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = dir
	t.Cleanup(func() { config.ProcBasePath = orig })
	cache.ResetCPUTimes()
	t.Cleanup(cache.ResetCPUTimes)
	return dir
}

func writeStat(t *testing.T, dir string, pid uint32, comm, flags string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, fmt.Sprint(pid)), 0o750); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S 2 0 0 0 -1 %s 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0", pid, comm, flags)
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(pid), "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestATenantProcessNamedLikeAKernelThreadIsNotOne(t *testing.T) {
	dir := emptyProc(t)
	writeStat(t, dir, 4100, "kworker/0:1", "4194560")
	if IsKernelThread(4100, "kworker/0:1") {
		t.Error("a process without PF_KTHREAD was classified as a kernel thread by its name")
	}
}

func TestAKernelThreadIsRecognisedByItsFlagWhateverItsName(t *testing.T) {
	dir := emptyProc(t)
	writeStat(t, dir, 4101, "oddly named) thread", "2129984")
	if !IsKernelThread(4101, "oddly named) thread") {
		t.Error("a PF_KTHREAD process was not classified as a kernel thread")
	}
}

func TestAnExitedProcessIsClassifiedByItsName(t *testing.T) {
	emptyProc(t)
	if !IsKernelThread(4102, "ksoftirqd/3") || IsKernelThread(4102, "nginx") {
		t.Error("the name fallback for an exited process changed")
	}
}

func TestAnUnreadableFlagsFieldFallsBackToTheName(t *testing.T) {
	dir := emptyProc(t)
	writeStat(t, dir, 4103, "kworker/1:0", "notanumber")
	if !IsKernelThread(4103, "kworker/1:0") {
		t.Error("a malformed flags field did not fall back to the name")
	}
	if err := os.WriteFile(filepath.Join(dir, "4103", "stat"), []byte("4103 (short) S 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsKernelThread(4103, "kworker/1:0") {
		t.Error("a short stat line did not fall back to the name")
	}
	if err := os.WriteFile(filepath.Join(dir, "4103", "stat"), []byte("no paren"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsKernelThread(4103, "kworker/1:0") {
		t.Error("a stat line without a comm did not fall back to the name")
	}
}

func TestTotalCPUCountsProcessesPastTheDisplayCut(t *testing.T) {
	emptyProc(t)
	n := config.TopProcessesLimit*2 + 5
	var evs []*events.Event
	kernelNS := map[uint32]uint64{}
	for i := 0; i < n; i++ {
		pid := uint32(5000 + i)
		evs = append(evs, &events.Event{PID: pid, ProcessName: fmt.Sprintf("app-%d", i)})
		kernelNS[pid] = uint64(100 * time.Millisecond)
	}
	evs = append(evs, &events.Event{PID: 6000, ProcessName: "kworker/0:2"})
	kernelNS[6000] = uint64(500 * time.Millisecond)

	got := GenerateProcessCPUReport(evs, time.Second, kernelNS)
	want := fmt.Sprintf("Total CPU usage: %.1f%%", float64(n)*10+50)
	if !strings.Contains(got, want) {
		t.Errorf("report = %q, want %q", got, want)
	}
	if !strings.Contains(got, "... and 5 more pod processes") {
		t.Errorf("report = %q, want the processes past the cut counted", got)
	}
	if strings.Count(got, "(app-") != config.TopProcessesLimit*2 {
		t.Errorf("report shows %d pod processes, want %d", strings.Count(got, "(app-"), config.TopProcessesLimit*2)
	}
}
