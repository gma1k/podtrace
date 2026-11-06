package filter

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/validation"
)

var readFile = os.ReadFile

// processStartTicks names the process instance holding a pid; replaceable so
// tests need no real processes.
var processStartTicks = procfs.StartTicks

type pidCacheEntry struct {
	result     bool
	at         time.Time
	generation uint64
	startTicks uint64
}

type CgroupFilter struct {
	cgroupPath  string
	cgroupPaths map[string]struct{}
	pidCache    map[uint32]pidCacheEntry
	pidCacheMu  sync.RWMutex
	pathsMu     sync.RWMutex
	now         func() time.Time
	ttl         time.Duration
	generation  atomic.Uint64
}

func NewCgroupFilter() *CgroupFilter {
	return &CgroupFilter{
		cgroupPaths: make(map[string]struct{}),
		pidCache:    make(map[uint32]pidCacheEntry),
	}
}

func (f *CgroupFilter) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

func (f *CgroupFilter) cacheTTL() time.Duration {
	if f.ttl > 0 {
		return f.ttl
	}
	return time.Duration(config.PIDCacheTTLSeconds) * time.Second
}

func (f *CgroupFilter) SetCgroupPath(path string) {
	f.pathsMu.Lock()
	f.cgroupPath = path
	f.cgroupPaths = make(map[string]struct{})
	if path != "" {
		f.cgroupPaths[path] = struct{}{}
	}
	f.generation.Add(1)
	f.pathsMu.Unlock()
	f.pidCacheMu.Lock()
	f.pidCache = make(map[uint32]pidCacheEntry)
	f.pidCacheMu.Unlock()
}

func (f *CgroupFilter) SetCgroupPaths(paths []string) {
	f.pathsMu.Lock()
	f.cgroupPath = ""
	f.cgroupPaths = make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		f.cgroupPaths[path] = struct{}{}
	}
	f.generation.Add(1)
	f.pathsMu.Unlock()
	f.pidCacheMu.Lock()
	f.pidCache = make(map[uint32]pidCacheEntry)
	f.pidCacheMu.Unlock()
}

// snapshotTargets copies the configured target paths, and the generation
// they belong to, under pathsMu. The agent calls SetCgroupPaths on every
// reconcile while IsPIDInCgroup runs on the event hot path.
func (f *CgroupFilter) snapshotTargets() ([]string, uint64) {
	f.pathsMu.RLock()
	defer f.pathsMu.RUnlock()
	targets := make([]string, 0, len(f.cgroupPaths)+1)
	if f.cgroupPath != "" {
		targets = append(targets, f.cgroupPath)
	}
	for p := range f.cgroupPaths {
		if p != "" {
			targets = append(targets, p)
		}
	}
	return targets, f.generation.Load()
}

// HasTargets reports whether any cgroup target is configured.
func (f *CgroupFilter) HasTargets() bool {
	f.pathsMu.RLock()
	defer f.pathsMu.RUnlock()
	if f.cgroupPath != "" {
		return true
	}
	for p := range f.cgroupPaths {
		if p != "" {
			return true
		}
	}
	return false
}

func (f *CgroupFilter) IsPIDInCgroup(pid uint32) bool {
	configuredTargets, generation := f.snapshotTargets()
	if len(configuredTargets) == 0 {
		return true
	}

	if !validation.ValidatePID(pid) {
		return false
	}

	if result, ok := f.cachedResult(pid, generation); ok {
		metricsexporter.RecordPIDCacheHit()
		return result
	}
	metricsexporter.RecordPIDCacheMiss()

	cgroupFile := fmt.Sprintf("%s/%d/cgroup", config.ProcBasePath, pid)
	if len(cgroupFile) > config.MaxCgroupFilePathLength {
		return false
	}
	startTicks, startKnown := processStartTicks(pid)
	data, err := readFile(cgroupFile)
	if err != nil {
		f.storeResult(pid, pidCacheEntry{result: false, generation: generation})
		return false
	}

	pidCgroupPath := ExtractCgroupPathFromProc(strings.TrimSpace(string(data)))
	if pidCgroupPath == "" {
		f.storeResult(pid, pidCacheEntry{result: false, generation: generation})
		return false
	}

	normalizedPID := NormalizeCgroupPath(pidCgroupPath)

	result := false
	for _, target := range configuredTargets {
		normalizedTarget := NormalizeCgroupPath(target)
		// If the configured target normalizes to empty (e.g. "/" or the cgroup base),
		// treat it as invalid to avoid accidentally matching everything.
		if normalizedTarget == "" {
			continue
		}
		if normalizedPID == normalizedTarget || strings.HasPrefix(normalizedPID, normalizedTarget+"/") {
			result = true
			break
		}
	}

	if !result || startKnown {
		f.storeResult(pid, pidCacheEntry{result: result, generation: generation, startTicks: startTicks})
	}
	return result
}

// cachedResult returns a cached verdict for pid computed against the current
// target generation.
func (f *CgroupFilter) cachedResult(pid uint32, generation uint64) (bool, bool) {
	f.pidCacheMu.RLock()
	cached, ok := f.pidCache[pid]
	f.pidCacheMu.RUnlock()
	if !ok || cached.generation != generation || f.clock().Sub(cached.at) >= f.cacheTTL() {
		return false, false
	}
	if !cached.result {
		return false, true
	}
	if start, known := processStartTicks(pid); known && start == cached.startTicks {
		return true, true
	}
	return false, false
}

// storeResult caches a verdict unless the target set changed while it was
// being computed.
func (f *CgroupFilter) storeResult(pid uint32, entry pidCacheEntry) {
	entry.at = f.clock()
	f.pidCacheMu.Lock()
	defer f.pidCacheMu.Unlock()
	if f.generation.Load() != entry.generation {
		return
	}
	if len(f.pidCache) >= config.MaxPIDCacheSize {
		evictTarget := int(float64(config.MaxPIDCacheSize) * config.PIDCacheEvictionRatio)
		for k := range f.pidCache {
			delete(f.pidCache, k)
			if len(f.pidCache) < evictTarget {
				break
			}
		}
	}
	f.pidCache[pid] = entry
}

func NormalizeCgroupPath(path string) string {
	path = strings.TrimPrefix(path, config.CgroupBasePath)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	return path
}

func ExtractCgroupPathFromProc(cgroupContent string) string {
	lines := strings.Split(cgroupContent, "\n")
	// Prefer cgroup v2 unified hierarchy line wherever it appears.
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}

	// Fallback to cgroup v1: pick a "cpu" controller if possible, else any valid line.
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			controllers := parts[1]
			if controllers == "cpu" || controllers == "cpu,cpuacct" || strings.Contains(controllers, "cpu") {
				return parts[2]
			}
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			return parts[2]
		}
	}
	return ""
}
