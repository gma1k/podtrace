package cache

import (
	"sort"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/procfs"
)

// ProcessCPUTime is a snapshot of /proc/<pid>/stat's utime+stime, captured at
// event-arrival time when the process is still alive.
type ProcessCPUTime struct {
	TotalNS    uint64
	BaselineNS uint64
	StartTicks uint64
}

const maxCPUTimeEntries = 16384

// cpuSampleInterval is how often one pid's /proc stat is re-read. Every event
// lands here, and on a busy node most come from a few hot processes; their
// CPU totals do not need a fresh read per event.
const cpuSampleInterval = time.Second

type cpuTimeEntry struct {
	ProcessCPUTime
	sampledAt time.Time
}

var (
	cpuTimeMu    sync.RWMutex
	cpuTimes            = map[uint32]cpuTimeEntry{}
	clockTicks   uint64 = 100
	clockTicksOK bool
	cpuNow       = time.Now
)

// SnapshotCPUTime reads /proc/<pid>/stat and stores the result in the
// per-PID cache, at most once per cpuSampleInterval for each pid.
func SnapshotCPUTime(pid uint32) {
	now := cpuNow()
	cpuTimeMu.RLock()
	prev, seen := cpuTimes[pid]
	cpuTimeMu.RUnlock()
	if seen && now.Sub(prev.sampledAt) < cpuSampleInterval {
		return
	}

	stat, err := procfs.ReadProcessStat(pid)
	if err != nil {
		return
	}

	ct := loadClockTicks()
	totalNS := (stat.UserTicks + stat.SystemTicks) * (1_000_000_000 / ct)

	cpuTimeMu.Lock()
	prev, seen = cpuTimes[pid]
	if !seen && len(cpuTimes) >= maxCPUTimeEntries {
		evictStalestCPUTimes()
	}
	cpuTimes[pid] = cpuTimeEntry{ProcessCPUTime: mergeCPUSample(prev.ProcessCPUTime, seen, totalNS, stat.StartTicks), sampledAt: now}
	cpuTimeMu.Unlock()
}

// evictStalestCPUTimes frees room in a full cache by dropping the eighth of
// its entries sampled longest ago, rather than every baseline at once.
// Callers hold cpuTimeMu.
func evictStalestCPUTimes() {
	type aged struct {
		pid uint32
		at  time.Time
	}
	all := make([]aged, 0, len(cpuTimes))
	for pid, e := range cpuTimes {
		all = append(all, aged{pid, e.sampledAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	drop := len(all) / 8
	if drop == 0 {
		drop = 1
	}
	for _, a := range all[:drop] {
		delete(cpuTimes, a.pid)
	}
}

// mergeCPUSample folds a new cumulative CPU sample into the cached snapshot.
// The baseline carries over only while the same process holds the pid.
func mergeCPUSample(prev ProcessCPUTime, seen bool, totalNS, startTicks uint64) ProcessCPUTime {
	baseline := totalNS
	if seen && prev.StartTicks == startTicks && totalNS >= prev.BaselineNS {
		baseline = prev.BaselineNS
	}
	return ProcessCPUTime{TotalNS: totalNS, BaselineNS: baseline, StartTicks: startTicks}
}

// GetCPUTime returns the cached snapshot for pid, or zero when nothing has
// been recorded.
func GetCPUTime(pid uint32) ProcessCPUTime {
	cpuTimeMu.RLock()
	t := cpuTimes[pid]
	cpuTimeMu.RUnlock()
	return t.ProcessCPUTime
}

// LookupCPUTime returns the cached snapshot for pid and whether there is one,
// so a baseline of zero can be told apart from no baseline at all.
func LookupCPUTime(pid uint32) (ProcessCPUTime, bool) {
	cpuTimeMu.RLock()
	t, ok := cpuTimes[pid]
	cpuTimeMu.RUnlock()
	return t.ProcessCPUTime, ok
}

// ResetCPUTimes clears the cache. Tests use it; production code does not.
func ResetCPUTimes() {
	cpuTimeMu.Lock()
	cpuTimes = map[uint32]cpuTimeEntry{}
	cpuTimeMu.Unlock()
}

// ClockTicks is AT_CLKTCK, the unit of /proc/<pid>/stat's CPU times, read
// once from the auxiliary vector and defaulting to 100.
func ClockTicks() uint64 {
	return loadClockTicks()
}

func loadClockTicks() uint64 {
	cpuTimeMu.RLock()
	ok := clockTicksOK
	v := clockTicks
	cpuTimeMu.RUnlock()
	if ok {
		return v
	}
	cpuTimeMu.Lock()
	defer cpuTimeMu.Unlock()
	if clockTicksOK {
		return clockTicks
	}
	if data, err := procfs.ReadFile("self/auxv"); err == nil {
		for i := 0; i+16 <= len(data); i += 16 {
			key := readUint64LE(data[i : i+8])
			if key == 17 {
				v := readUint64LE(data[i+8 : i+16])
				if v > 0 {
					clockTicks = v
				}
				break
			}
		}
	}
	clockTicksOK = true
	return clockTicks
}

func readUint64LE(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
