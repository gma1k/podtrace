package cache

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/podtrace/podtrace/internal/procfs"
)

// ProcessCPUTime is a snapshot of /proc/<pid>/stat's utime+stime, captured at
// event-arrival time when the process is still alive. Short-lived processes
// (runc helpers, exec'd commands) are gone by the time the diagnose report
// renders, so reading /proc/<pid>/stat at report time always returns 0 —
// this cache preserves the last-seen value so the report can attribute CPU
// to terminated processes.
type ProcessCPUTime struct {
	TotalNS uint64 // (utime + stime) converted to nanoseconds
}

const maxCPUTimeEntries = 16384

var (
	cpuTimeMu    sync.RWMutex
	cpuTimes     = map[uint32]ProcessCPUTime{}
	clockTicks   uint64 = 100
	clockTicksOK bool
)

// SnapshotCPUTime reads /proc/<pid>/stat once and stores the result in the
// per-PID cache. Safe to call multiple times per PID — later calls overwrite
// with the most recent sample so accumulated CPU is captured.
func SnapshotCPUTime(pid uint32) {
	data, err := procfs.ReadFile(fmt.Sprintf("%d/stat", pid))
	if err != nil {
		return
	}
	// /proc/<pid>/stat fields are space-separated except the (comm) field
	// which is parenthesized and may contain spaces. utime/stime are fields
	// 14 and 15 (1-indexed), which become 13/14 (0-indexed) AFTER the
	// `(comm)` chunk. Find the last ')' to skip the comm safely.
	s := string(data)
	rp := strings.LastIndex(s, ")")
	if rp < 0 || rp+2 >= len(s) {
		return
	}
	after := s[rp+2:]
	fields := strings.Fields(after)
	// In `after`, field 0 is the state char; field 11 is utime, field 12 is
	// stime. (Original 0-indexed positions were 13 and 14, but two were
	// consumed by pid and comm before "after".)
	if len(fields) < 13 {
		return
	}
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)

	ct := loadClockTicks()
	totalNS := (utime + stime) * (1_000_000_000 / ct)

	cpuTimeMu.Lock()
	if len(cpuTimes) >= maxCPUTimeEntries {
		if _, exists := cpuTimes[pid]; !exists {
			cpuTimes = make(map[uint32]ProcessCPUTime, maxCPUTimeEntries)
		}
	}
	cpuTimes[pid] = ProcessCPUTime{TotalNS: totalNS}
	cpuTimeMu.Unlock()
}

// GetCPUTime returns the cached snapshot for pid, or zero when nothing has
// been recorded.
func GetCPUTime(pid uint32) ProcessCPUTime {
	cpuTimeMu.RLock()
	t := cpuTimes[pid]
	cpuTimeMu.RUnlock()
	return t
}

// ResetCPUTimes clears the cache. Tests use it; production code does not.
func ResetCPUTimes() {
	cpuTimeMu.Lock()
	cpuTimes = map[uint32]ProcessCPUTime{}
	cpuTimeMu.Unlock()
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
	// AT_CLKTCK (key 17) in /proc/self/auxv carries the clock ticks per
	// second. Fallback to 100 (USER_HZ on most x86_64 kernels) when unavail.
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
