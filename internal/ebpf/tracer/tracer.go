package tracer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/podtrace/podtrace/internal/analysis/criticalpath"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/cache"
	"github.com/podtrace/podtrace/internal/ebpf/filter"
	"github.com/podtrace/podtrace/internal/ebpf/loader"
	"github.com/podtrace/podtrace/internal/ebpf/parser"
	"github.com/podtrace/podtrace/internal/ebpf/probes"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/redactor"
	"github.com/podtrace/podtrace/internal/resource"
	"github.com/podtrace/podtrace/internal/validation"
)

type stackTraceValue struct {
	IPs [config.MaxStackDepth]uint64
	Nr  uint32
	Pad uint32
}

type Tracer struct {
	collection               *ebpf.Collection
	links                    []link.Link
	probeGroupsMu            sync.Mutex
	probeGroups              map[probes.ProbeGroup][]link.Link
	reader                   *ringbuf.Reader
	filter                   *filter.CgroupFilter
	containerID              string
	containerPID             uint32
	processNameCache         *cache.LRUCache
	pathCache                *cache.PathCache
	resourceMonitor          *resource.ResourceMonitor
	cgroupPath               string
	useUserspaceCgroupFilter bool
	targetCgroupID           uint64
	cpAnalyzer               *criticalpath.Analyzer
	piiRedactor              *redactor.Redactor
}

// roundUpPow2 rounds n up to the nearest power of two, minimum 4096.
func roundUpPow2(n uint32) uint32 {
	if n < 4096 {
		return 4096
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n + 1
}

var _ TracerInterface = (*Tracer)(nil)

func NewTracer() (*Tracer, error) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		logger.Warn("Failed to set dumpable flag", zap.Error(err))
	}

	var rlim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlim); err == nil {
		if rlim.Cur < config.MemlockLimitBytes {
			originalMax := rlim.Max
			if rlim.Max < config.MemlockLimitBytes {
				rlim.Max = config.MemlockLimitBytes
			}
			rlim.Cur = config.MemlockLimitBytes
			if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
				rlim.Cur = rlim.Max
				if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
					rlim.Max = originalMax
					if err := rlimit.RemoveMemlock(); err != nil {
						logger.Warn("Failed to increase memlock limit", zap.Error(err))
					}
				}
			}
		}
	} else {
		if err := rlimit.RemoveMemlock(); err != nil {
			logger.Warn("Failed to remove memlock limit", zap.Error(err))
		}
	}

	spec, err := loader.LoadPodtrace()
	if err != nil {
		return nil, err
	}

	// Patch ring buffer size (must be power-of-2 multiple of page size).
	rbSize := roundUpPow2(uint32(config.RingBufferSizeKB * 1024))
	if m, ok := spec.Maps["events"]; ok {
		m.MaxEntries = rbSize
	}
	// Patch hash map sizes.
	hashSize := uint32(config.BPFHashMapSize)
	for name, m := range spec.Maps {
		if m.Type == ebpf.Hash {
			spec.Maps[name].MaxEntries = hashSize
		}
	}

	var opts ebpf.CollectionOptions
	if config.BTFFilePath != "" {
		if _, err := os.Stat(config.BTFFilePath); err == nil {
			if kspec, err := btf.LoadSpec(config.BTFFilePath); err == nil {
				opts.Programs.KernelTypes = kspec
			} else {
				logger.Warn("Failed to load external BTF file", zap.String("path", config.BTFFilePath), zap.Error(err))
			}
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, NewCollectionError(err)
	}

	// Initialize configurable alert thresholds in the BPF map.
	if threshMap, ok := coll.Maps["alert_thresholds"]; ok && threshMap != nil {
		thresholds := []uint32{
			uint32(config.AlertWarnPct),
			uint32(config.AlertCritPct),
			uint32(config.AlertEmergPct),
		}
		for i, v := range thresholds {
			k := uint32(i)
			val := v
			if err := threshMap.Update(&k, &val, ebpf.UpdateAny); err != nil {
				logger.Warn("Failed to set alert threshold", zap.Int("index", i), zap.Uint32("value", val), zap.Error(err))
			}
		}
	}

	links, err := probes.AttachProbes(coll)
	if err != nil {
		coll.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
		return nil, NewRingBufferError(err)
	}

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	processCache := cache.NewLRUCache(config.CacheMaxSize, ttl)

	t := &Tracer{
		collection:               coll,
		links:                    links,
		probeGroups:              make(map[probes.ProbeGroup][]link.Link),
		reader:                   rd,
		filter:                   filter.NewCgroupFilter(),
		processNameCache:         processCache,
		pathCache:                cache.NewPathCache(),
		useUserspaceCgroupFilter: true,
	}

	if config.CriticalPathEnabled {
		window := time.Duration(config.CriticalPathWindowMS) * time.Millisecond
		t.cpAnalyzer = criticalpath.New(window, func(cp criticalpath.CriticalPath) {
			fields := make([]zap.Field, 0, len(cp.Segments)+2)
			fields = append(fields, zap.Uint32("pid", cp.PID), zap.Duration("total", cp.TotalLatency))
			for _, s := range cp.Segments {
				fields = append(fields, zap.String(s.Label, fmt.Sprintf("%.1f%%", s.Fraction*100)))
			}
			logger.Info("Critical path", fields...)
		})
	}

	if config.RedactPII {
		t.piiRedactor = redactor.Default()
	}

	return t, nil
}

func (t *Tracer) AttachToCgroup(cgroupPath string) error {
	containerSubPath := filepath.Join(cgroupPath, "container")
	if _, err := os.Stat(filepath.Join(containerSubPath, "cgroup.procs")); err == nil {
		logger.Debug("Found CRI-O container subfolder, using it for precise cgroup filtering",
			zap.String("parent_path", cgroupPath),
			zap.String("container_path", containerSubPath))
		cgroupPath = containerSubPath
	}

	t.filter.SetCgroupPath(cgroupPath)
	t.cgroupPath = cgroupPath

	if cgroupPath != "" && filter.NormalizeCgroupPath(cgroupPath) == "" && os.Getenv("PODTRACE_ALLOW_ROOT_CGROUP") != "1" {
		return fmt.Errorf("podtrace: resolved cgroup path %q normalizes to root; refusing to attach (set PODTRACE_ALLOW_ROOT_CGROUP=1 to override)", cgroupPath)
	}

	if t.containerPID == 0 && cgroupPath != "" {
		if pid := readFirstPIDFromCgroupProcs(cgroupPath); pid != 0 {
			t.containerPID = pid
		}
	}

	if t.collection != nil && t.collection.Maps != nil {
		if targetMap, ok := t.collection.Maps["target_cgroup_id"]; ok && targetMap != nil {
			if isCgroupV2Base(config.CgroupBasePath) {
				if cgid, err := getCgroupIDFromPath(cgroupPath); err == nil && cgid != 0 {
					t.targetCgroupID = cgid
					zero := uint32(0)
					if err := targetMap.Update(&zero, &cgid, ebpf.UpdateAny); err != nil {
						logger.Warn("Failed to update target_cgroup_id map", zap.Error(err), zap.Uint64("cgroup_id", cgid))
					} else {
						logger.Debug("Set target cgroup ID for in-kernel filtering", zap.Uint64("cgroup_id", cgid), zap.String("cgroup_path", cgroupPath))
					}
					if os.Getenv("PODTRACE_DISABLE_USERSPACE_CGROUP_FILTER") == "1" {
						t.useUserspaceCgroupFilter = false
					}
				} else {
					logger.Debug("Could not get cgroup ID from path", zap.Error(err), zap.String("cgroup_path", cgroupPath))
				}
			} else {
				logger.Debug("Cgroup v2 not detected, using userspace filtering only", zap.String("cgroup_base", config.CgroupBasePath))
			}
		}
	}
	logger.Debug("Attached to cgroup", zap.String("cgroup_path", cgroupPath), zap.Uint32("container_pid", t.containerPID), zap.Uint64("target_cgroup_id", t.targetCgroupID), zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter))
	return nil
}

func readFirstPIDFromCgroupProcs(cgroupPath string) uint32 {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(line, "%d", &pid); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

func isCgroupV2Base(basePath string) bool {
	controllersPath := filepath.Join(basePath, "cgroup.controllers")
	if _, err := os.Stat(controllersPath); err == nil {
		return true
	}
	return false
}

func getCgroupIDFromPath(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0, fmt.Errorf("unsupported stat type for cgroup path")
	}
	return sys.Ino, nil
}

func (t *Tracer) SetContainerID(containerID string) error {
	t.containerID = containerID
	dnsLinks := probes.AttachDNSProbesWithPID(t.collection, containerID, t.containerPID)
	if len(dnsLinks) > 0 {
		t.links = append(t.links, dnsLinks...)
	}
	syncLinks := probes.AttachSyncProbesWithPID(t.collection, containerID, t.containerPID)
	if len(syncLinks) > 0 {
		t.links = append(t.links, syncLinks...)
	}
	dbLinks := probes.AttachDBProbesWithPID(t.collection, containerID, t.containerPID)
	if len(dbLinks) > 0 {
		t.links = append(t.links, dbLinks...)
	}
	poolLinks := probes.AttachPoolProbesWithPID(t.collection, containerID, t.containerPID)
	if len(poolLinks) > 0 {
		t.links = append(t.links, poolLinks...)
	}
	tlsLinks := probes.AttachTLSProbesWithPID(t.collection, containerID, t.containerPID)
	if len(tlsLinks) > 0 {
		t.links = append(t.links, tlsLinks...)
	}
	t.links = append(t.links, probes.AttachRedisProbesWithPID(t.collection, containerID, t.containerPID)...)
	t.links = append(t.links, probes.AttachMemcachedProbesWithPID(t.collection, containerID, t.containerPID)...)
	t.links = append(t.links, probes.AttachKafkaProbesWithPID(t.collection, containerID, t.containerPID)...)
	t.links = append(t.links, probes.AttachFastCGIProbes(t.collection)...)
	t.links = append(t.links, probes.AttachGRPCProbes(t.collection)...)
	return nil
}

func (t *Tracer) Start(ctx context.Context, eventChan chan<- *events.Event) error {
	errorLimiter := newErrorRateLimiter()
	slidingWindow := newSlidingWindow(config.DefaultSlidingWindowSize, config.DefaultSlidingWindowBuckets)
	circuitBreaker := newCircuitBreaker(config.DefaultCircuitBreakerThreshold, config.DefaultCircuitBreakerTimeout)
	stackMap := t.collection.Maps["stack_traces"]

	if t.cgroupPath != "" {
		limitsMap := t.collection.Maps["cgroup_limits"]
		alertsMap := t.collection.Maps["cgroup_alerts"]
		if limitsMap != nil && alertsMap != nil {
			rm, err := resource.NewResourceMonitor(t.cgroupPath, limitsMap, alertsMap, eventChan, "")
			if err != nil {
				logger.Warn("Failed to create resource monitor", zap.Error(err), zap.String("cgroup_path", t.cgroupPath))
			} else {
				t.resourceMonitor = rm
				logger.Debug("Resource monitor initialized", zap.String("cgroup_path", t.cgroupPath))
				rm.Start(ctx)
				logger.Debug("Resource monitor started")
			}
		} else {
			logger.Warn("Resource monitor maps not found in BPF collection")
		}
	} else {
		logger.Debug("Cgroup path not set, skipping resource monitor initialization")
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if t.pathCache != nil {
					t.pathCache.CleanupExpired()
				}
				t.pollBPFMapUtilization()
			}
		}
	}()

	if config.ManagementPort > 0 {
		go t.serveManagementAPI(ctx, config.ManagementPort)
	}

	var eventsCollected int64
	var eventsFiltered int64
	var eventsParsed int64
	var filteringDisabled bool
	startTime := time.Now()
	eventCollectionTicker := time.NewTicker(5 * time.Second)
	defer eventCollectionTicker.Stop()

	logger.Info("Starting event collection",
		zap.String("cgroup_path", t.cgroupPath),
		zap.Uint32("container_pid", t.containerPID),
		zap.Uint64("target_cgroup_id", t.targetCgroupID),
		zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter))

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-eventCollectionTicker.C:
				elapsed := time.Since(startTime)
				if !filteringDisabled && eventsParsed > 10 && eventsCollected == 0 && elapsed > 10*time.Second {
					logger.Warn("Events being parsed but all filtered - disabling filtering as fallback",
						zap.Int64("events_parsed", eventsParsed),
						zap.Int64("events_filtered", eventsFiltered),
						zap.Int64("events_collected", eventsCollected),
						zap.Uint64("target_cgroup_id", t.targetCgroupID),
						zap.String("cgroup_path", t.cgroupPath),
						zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter))
					filteringDisabled = true
					t.useUserspaceCgroupFilter = false
					t.targetCgroupID = 0
					if t.collection != nil && t.collection.Maps != nil {
						if targetMap, ok := t.collection.Maps["target_cgroup_id"]; ok && targetMap != nil {
							zero := uint32(0)
							zeroCgid := uint64(0)
							_ = targetMap.Update(&zero, &zeroCgid, ebpf.UpdateAny)
							logger.Info("Cleared kernel-side cgroup filter")
						}
					}
				} else if eventsParsed == 0 && elapsed > 15*time.Second {
					logger.Warn("No events parsed from ring buffer after 15 seconds - check eBPF program attachment",
						zap.Uint64("target_cgroup_id", t.targetCgroupID),
						zap.String("cgroup_path", t.cgroupPath),
						zap.Duration("elapsed", elapsed),
						zap.Int("links_attached", len(t.links)))
					logger.Warn("If running in a container (e.g. DaemonSet), ensure host /sys/fs/cgroup and /proc are mounted and PODTRACE_CGROUP_BASE / PODTRACE_PROC_BASE point at them; see installation doc 'Running as a DaemonSet'")
				} else if eventsCollected == 0 && eventsParsed > 0 && elapsed > 10*time.Second {
					logger.Warn("Events parsed but none collected - filtering may be too strict",
						zap.Int64("events_parsed", eventsParsed),
						zap.Int64("events_filtered", eventsFiltered),
						zap.Uint64("target_cgroup_id", t.targetCgroupID),
						zap.String("cgroup_path", t.cgroupPath),
						zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter),
						zap.Duration("elapsed", elapsed))
					if t.useUserspaceCgroupFilter {
						logger.Warn("Running in a container (e.g. DaemonSet)? Set PODTRACE_CGROUP_BASE and PODTRACE_PROC_BASE to the host's cgroup and proc mount paths so the target pod's cgroup is visible and filtering can match events",
							zap.String("cgroup_base", config.CgroupBasePath),
							zap.String("proc_base", config.ProcBasePath))
					}
				}
			}
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in event reader",
					zap.Any("panic", r),
					zap.ByteString("stack", debug.Stack()))
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := t.reader.Read()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, ringbuf.ErrClosed) || strings.Contains(err.Error(), "closed") {
					return
				}

				if !circuitBreaker.canProceed() {
					continue
				}

				category := classifyError(err)
				if category == ErrorCategoryTransient {
					circuitBreaker.recordSuccess()
				} else {
					circuitBreaker.recordFailure()
				}

				slidingWindow.addError()
				errorRate := slidingWindow.getErrorRate()
				metricsexporter.RecordRingBufferDrop()

				if config.ErrorBackoffEnabled && errorLimiter.shouldLog() {
					if errorRate > config.HighErrorCountThreshold {
						logger.Warn("High ring buffer error rate, events may be dropped",
							zap.Int("error_rate", errorRate),
							zap.String("error_category", errorCategoryString(category)),
							zap.Duration("window", config.DefaultSlidingWindowSize))
					} else {
						logger.Error("Error reading ring buffer", zap.Error(err))
					}
				} else if !config.ErrorBackoffEnabled {
					if errorRate > config.HighErrorCountThreshold {
						logger.Warn("High ring buffer error rate, events may be dropped",
							zap.Int("error_rate", errorRate),
							zap.Duration("window", config.DefaultSlidingWindowSize))
					} else {
						logger.Error("Error reading ring buffer", zap.Error(err))
					}
				}
				continue
			}

			if circuitBreaker.canProceed() {
				circuitBreaker.recordSuccess()
			}

			processingStart := time.Now()
			event := parser.ParseEvent(record.RawSample)
			if event != nil {
				eventsParsed++
				if stackMap != nil && event.StackKey != 0 {
					var stack stackTraceValue
					key := event.StackKey
					if err := stackMap.Lookup(&key, &stack); err == nil {
						n := int(stack.Nr)
						if n > len(stack.IPs) {
							n = len(stack.IPs)
						}
						if n > 0 {
							frames := make([]uint64, n)
							copy(frames, stack.IPs[:n])
							event.Stack = frames
						}
					}
				}
				if event.ProcessName == "" {
					event.ProcessName = t.getProcessNameQuick(event.PID)
				}
				event.ProcessName = validation.SanitizeProcessName(event.ProcessName)

				if t.piiRedactor != nil {
					t.piiRedactor.Redact(event)
				}
				if t.cpAnalyzer != nil {
					t.cpAnalyzer.Feed(event)
				}

				if event.Target != "" && event.Target != "<disconnected>" {
					cacheKey := fmt.Sprintf("%d:%s", event.PID, event.Target)
					if cached, ok := t.pathCache.Get(cacheKey); ok {
						event.Target = cached
					} else {
						t.pathCache.Set(cacheKey, event.Target)
					}
				}

				if event.Error != 0 {
					metricsexporter.RecordError(event.TypeString(), event.Error)
				}

				allowed := true
				if filteringDisabled {
					// Fallback mode: allow all events
					allowed = true
				} else if t.targetCgroupID != 0 && event.CgroupID != 0 {
					allowed = (event.CgroupID == t.targetCgroupID)
					if !allowed {
						eventsFiltered++
						// Log first few mismatches for debugging, then throttle
						if eventsFiltered <= 5 || time.Now().Unix()%10 == 0 {
							logger.Debug("Event filtered by cgroup ID mismatch",
								zap.Uint64("event_cgroup_id", event.CgroupID),
								zap.Uint64("target_cgroup_id", t.targetCgroupID),
								zap.Uint32("pid", event.PID),
								zap.String("process", event.ProcessName))
						}
					}
				} else if t.useUserspaceCgroupFilter {
					allowed = t.filter.IsPIDInCgroup(event.PID)
					if !allowed {
						eventsFiltered++
						if eventsFiltered <= 5 || time.Now().Unix()%10 == 0 {
							logger.Debug("Event filtered by userspace PID cgroup check",
								zap.Uint32("pid", event.PID),
								zap.String("process", event.ProcessName),
								zap.String("cgroup_path", t.cgroupPath))
						}
					}
				} else {
					if eventsParsed <= 5 {
						logger.Debug("No cgroup filtering active, allowing all events",
							zap.Uint64("event_cgroup_id", event.CgroupID),
							zap.Uint64("target_cgroup_id", t.targetCgroupID),
							zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter))
					}
				}

				if allowed {
					select {
					case <-ctx.Done():
						parser.PutEvent(event)
						return
					case eventChan <- event:
						eventsCollected++
						if eventsCollected <= 5 {
							logger.Debug("Event collected",
								zap.Uint64("cgroup_id", event.CgroupID),
								zap.Uint32("pid", event.PID),
								zap.String("process", event.ProcessName),
								zap.String("type", event.TypeString()))
						}
						metricsexporter.RecordEventProcessingLatency(time.Since(processingStart))
					default:
						metricsexporter.RecordRingBufferDrop()
						parser.PutEvent(event)
					}
				} else {
					parser.PutEvent(event)
				}
			}
		}
	}()

	return nil
}

func (t *Tracer) Stop() error {
	if t.reader != nil {
		_ = t.reader.Close()
	}

	for _, l := range t.links {
		_ = l.Close()
	}

	if t.collection != nil {
		t.collection.Close()
	}

	if t.processNameCache != nil {
		t.processNameCache.Close()
	}

	if t.pathCache != nil {
		t.pathCache.Clear()
	}

	if t.resourceMonitor != nil {
		t.resourceMonitor.Stop()
	}

	return nil
}

func (t *Tracer) getProcessNameQuick(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	if name, ok := t.processNameCache.Get(pid); ok {
		return name
	}

	metricsexporter.RecordProcessCacheMiss()

	name := ""

	cmdlinePath := fmt.Sprintf("%s/%d/cmdline", config.ProcBasePath, pid)
	if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			name = parts[0]
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
	}

	if name == "" {
		statPath := fmt.Sprintf("%s/%d/stat", config.ProcBasePath, pid)
		if data, err := os.ReadFile(statPath); err == nil {
			statStr := string(data)
			start := strings.Index(statStr, "(")
			end := strings.LastIndex(statStr, ")")
			if start >= 0 && end > start {
				name = statStr[start+1 : end]
			}
		}
	}

	if name == "" {
		commPath := fmt.Sprintf("%s/%d/comm", config.ProcBasePath, pid)
		if data, err := os.ReadFile(commPath); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	sanitized := validation.SanitizeProcessName(name)
	t.processNameCache.Set(pid, sanitized)
	return sanitized
}

// pollBPFMapUtilization reads fill ratios for key BPF hash maps and records them.
func (t *Tracer) pollBPFMapUtilization() {
	if t.collection == nil {
		return
	}
	tracked := []string{"stack_traces", "start_times", "socket_conns", "db_queries", "pool_states"}
	for _, name := range tracked {
		m, ok := t.collection.Maps[name]
		if !ok || m == nil {
			continue
		}
		info, err := m.Info()
		if err != nil || info.MaxEntries == 0 {
			continue
		}
		// Count entries via iterator (no Count() method in cilium/ebpf).
		var count uint32
		var key, val []byte
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			count++
		}
		ratio := float64(count) / float64(info.MaxEntries)
		metricsexporter.RecordBPFMapUtilization(name, ratio)
	}
}

// ActiveProbeGroups returns the set of probe groups currently enabled.
func (t *Tracer) ActiveProbeGroups() []probes.ProbeGroup {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	result := make([]probes.ProbeGroup, 0, len(t.probeGroups))
	for g := range t.probeGroups {
		result = append(result, g)
	}
	return result
}

// DisableProbeGroup closes all links associated with the given group.
func (t *Tracer) DisableProbeGroup(g probes.ProbeGroup) error {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	ls, ok := t.probeGroups[g]
	if !ok || len(ls) == 0 {
		return nil
	}
	for _, l := range ls {
		_ = l.Close()
	}
	delete(t.probeGroups, g)
	logger.Info("Probe group disabled", zap.String("group", string(g)))
	return nil
}

// serveManagementAPI starts a lightweight HTTP server for probe group management.
func (t *Tracer) serveManagementAPI(ctx context.Context, port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		groups := t.ActiveProbeGroups()
		strs := make([]string, len(groups))
		for i, g := range groups {
			strs[i] = string(g)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active_groups": strs})
	})
	mux.HandleFunc("/probes/", func(w http.ResponseWriter, r *http.Request) {
		// Expect /probes/{group}/disable
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/probes/"), "/")
		if len(parts) != 2 || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		group := probes.ProbeGroup(parts[0])
		action := parts[1]
		switch action {
		case "disable":
			if err := t.DisableProbeGroup(group); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	logger.Info("Management API listening", zap.Int("port", port))
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Warn("Management API server error", zap.Error(err))
	}
}

func WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
