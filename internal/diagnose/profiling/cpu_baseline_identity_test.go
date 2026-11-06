package profiling

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
)

func TestABaselineFromAnEarlierHolderOfThePIDIsNotSubtracted(t *testing.T) {
	ticks := clockTicksPerSecond()
	fakeProcWithProcess(t, 4324, 10*ticks, 1*ticks, "86400.00 1.00\n")
	cache.SnapshotCPUTime(4324)
	stat := fmt.Sprintf("4324 (new) S 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 0 0", 3600*ticks, 20*ticks)
	if err := os.WriteFile(filepath.Join(config.ProcBasePath, "4324", "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := procCPUDeltaNS(4324, 30*time.Second); got != 0 {
		t.Errorf("delta = %v; a day-old process that took over the pid was charged its lifetime minus another process's baseline", time.Duration(got))
	}
}

func TestTheSameProcessIsChargedTheGrowthSinceItsBaseline(t *testing.T) {
	ticks := clockTicksPerSecond()
	fakeProcWithProcess(t, 4325, 10*ticks, 1*ticks, "86400.00 1.00\n")
	cache.SnapshotCPUTime(4325)
	stat := fmt.Sprintf("4325 (app) S 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 0 0", 4*ticks, 10*ticks)
	if err := os.WriteFile(filepath.Join(config.ProcBasePath, "4325", "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, want := procCPUDeltaNS(4325, 30*time.Second), uint64(3*time.Second); got != want {
		t.Errorf("delta = %v, want %v", time.Duration(got), time.Duration(want))
	}
}
