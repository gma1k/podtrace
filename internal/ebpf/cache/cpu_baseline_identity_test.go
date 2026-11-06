package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeStatStarted(t *testing.T, base string, pid uint32, utime, startTicks uint64) {
	t.Helper()
	dir := filepath.Join(base, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (worker) S 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 0 0", pid, utime, startTicks)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAReusedPIDStartsANewBaseline(t *testing.T) {
	base, now := withFakeProc(t)
	const pid uint32 = 4200
	writeStatStarted(t, base, pid, 500, 100)
	SnapshotCPUTime(pid)

	writeStatStarted(t, base, pid, 700, 900)
	*now = now.Add(2 * cpuSampleInterval)
	SnapshotCPUTime(pid)

	got := GetCPUTime(pid)
	if got.BaselineNS != got.TotalNS || got.StartTicks != 900 {
		t.Fatalf("snapshot = %+v; the new process inherited the old one's baseline", got)
	}
}

func TestTheSameProcessKeepsItsFirstBaseline(t *testing.T) {
	base, now := withFakeProc(t)
	const pid uint32 = 4201
	writeStatStarted(t, base, pid, 500, 100)
	SnapshotCPUTime(pid)
	first := GetCPUTime(pid).TotalNS

	writeStatStarted(t, base, pid, 700, 100)
	*now = now.Add(2 * cpuSampleInterval)
	SnapshotCPUTime(pid)

	if got := GetCPUTime(pid); got.BaselineNS != first || got.TotalNS <= first {
		t.Fatalf("snapshot = %+v, want baseline %d kept and the total advanced", got, first)
	}
}

func TestASampleBelowTheBaselineStartsANewOne(t *testing.T) {
	merged := mergeCPUSample(ProcessCPUTime{TotalNS: 9, BaselineNS: 9, StartTicks: 5}, true, 4, 5)
	if merged.BaselineNS != 4 {
		t.Fatalf("baseline = %d; a total below the baseline cannot be the same counter", merged.BaselineNS)
	}
}
