package tracer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/podtrace/podtrace/internal/procfs"
	"github.com/podtrace/podtrace/internal/redactor"
	"github.com/podtrace/podtrace/internal/sysfs"
	"github.com/podtrace/podtrace/internal/validation"
)

type stackTraceValue struct {
	IPs [config.MaxStackDepth]uint64
	Nr  uint32
	Pad uint32
}

// ProfilingController is implemented by internal/profiling.Handler and
// registered via SetProfilingController before Start() to expose
// /profile/* routes on the management port HTTP server.
type ProfilingController interface {
	HTTPStart(w http.ResponseWriter, r *http.Request)
	HTTPStatus(w http.ResponseWriter, r *http.Request)
	HTTPResult(w http.ResponseWriter, r *http.Request)
}

// ProfilingControllerSetter is satisfied by *Tracer.  main.go uses a type
// assertion against this interface so it can wire in the profiling handler
// without modifying TracerInterface.
type ProfilingControllerSetter interface {
	SetProfilingController(ctrl ProfilingController)
}

type Tracer struct {
	collection     *ebpf.Collection
	links          []link.Link
	probeGroupsMu  sync.Mutex
	probeGroups    map[probes.ProbeGroup][]link.Link
	dnsPacketLinks map[string][]link.Link

	intentionallyDisabled    map[probes.ProbeGroup]struct{}
	detachWarned             map[probes.ProbeGroup]struct{}
	reader                   *ringbuf.Reader
	filter                   *filter.CgroupFilter
	containerID              string
	containerPID             uint32
	processNameCache         *cache.LRUCache
	pathCache                *cache.PathCache
	resourceMgr              *resourceMonitorManager
	cgroupPath               string
	lastDNSDrops             uint64
	cgroupPaths              []string
	useUserspaceCgroupFilter atomic.Bool
	targetCgroupID           atomic.Uint64
	targetCgroupIDs          atomic.Pointer[map[uint64]struct{}]
	cgroupWriteMu            sync.Mutex
	cpAnalyzer               *criticalpath.Analyzer
	piiRedactor              *redactor.Redactor
	profilingCtrl            ProfilingController
}

// registerGroupLinks records freshly attached links under their probe group
// (so Disable/EnableProbeGroup can manage them) and in the flat registry
// Stop() closes.
func (t *Tracer) registerGroupLinks(g probes.ProbeGroup, ls []link.Link) {
	if len(ls) == 0 {
		return
	}
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	t.probeGroups[g] = append(t.probeGroups[g], ls...)
	t.links = append(t.links, ls...)
}

func (t *Tracer) addLinks(ls []link.Link) {
	if len(ls) == 0 {
		return
	}
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	t.links = append(t.links, ls...)
}

func (t *Tracer) linkCount() int {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	return len(t.links)
}

// attachGroupUprobes re-attaches the container-scoped probes belonging to a
// group, using the most recent SetContainerIDs target.
func (t *Tracer) attachGroupUprobes(g probes.ProbeGroup) []link.Link {
	coll := t.collection
	if coll == nil {
		return nil
	}
	id, pid := t.containerID, t.containerPID
	switch g {
	case probes.GroupTLS:
		if id == "" {
			return nil
		}
		var ls []link.Link
		ls = append(ls, probes.AttachDNSProbesWithPID(coll, id, pid)...)
		ls = append(ls, probes.AttachSyncProbesWithPID(coll, id, pid)...)
		ls = append(ls, probes.AttachTLSProbesWithPID(coll, id, pid)...)
		return ls
	case probes.GroupDatabase:
		if id == "" {
			return nil
		}
		return probes.AttachDBProbesWithPID(coll, id, pid)
	case probes.GroupPool:
		if id == "" {
			return nil
		}
		return probes.AttachPoolProbesWithPID(coll, id, pid)
	case probes.GroupCache:
		if id == "" {
			return nil
		}
		var ls []link.Link
		ls = append(ls, probes.AttachRedisProbesWithPID(coll, id, pid)...)
		ls = append(ls, probes.AttachMemcachedProbesWithPID(coll, id, pid)...)
		return ls
	case probes.GroupMessaging:
		if id == "" {
			return nil
		}
		return probes.AttachKafkaProbesWithPID(coll, id, pid)
	case probes.GroupFastCGI:
		return probes.AttachFastCGIProbes(coll)
	case probes.GroupNetwork:
		return probes.AttachGRPCProbes(coll)
	}
	return nil
}

// syncDNSPacketProbes reconciles the per-cgroup dns_egress/dns_ingress
// attachments with the current target set.
func (t *Tracer) syncDNSPacketProbes(paths []string) {
	if t.collection == nil {
		return
	}
	want := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p != "" {
			want[p] = struct{}{}
		}
	}

	t.probeGroupsMu.Lock()
	if t.dnsPacketLinks == nil {
		t.dnsPacketLinks = map[string][]link.Link{}
	}
	for p, ls := range t.dnsPacketLinks {
		if _, ok := want[p]; ok {
			continue
		}
		for _, l := range ls {
			_ = l.Close()
		}
		delete(t.dnsPacketLinks, p)
	}
	var missing []string
	for p := range want {
		if _, ok := t.dnsPacketLinks[p]; !ok {
			missing = append(missing, p)
		}
	}
	t.probeGroupsMu.Unlock()

	for _, p := range missing {
		ls := probes.AttachDNSPacketProbes(t.collection, []string{p})
		t.probeGroupsMu.Lock()
		t.dnsPacketLinks[p] = ls
		t.probeGroupsMu.Unlock()
	}
}

// SetProfilingController wires an optional profiling controller into the
// management API server.
func (t *Tracer) SetProfilingController(ctrl ProfilingController) {
	t.profilingCtrl = ctrl
}

// loadCgroupIDs returns the current cgroup-ID filter set.
func (t *Tracer) loadCgroupIDs() map[uint64]struct{} {
	if p := t.targetCgroupIDs.Load(); p != nil {
		return *p
	}
	return nil
}

// storeCgroupIDs atomically publishes a new cgroup-ID filter set.
func (t *Tracer) storeCgroupIDs(m map[uint64]struct{}) {
	t.targetCgroupIDs.Store(&m)
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
	if err := setDumpable(); err != nil {
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

	rbBytes := config.RingBufferSizeKB
	if rbBytes > 0 && rbBytes <= math.MaxInt/1024 {
		rbBytes *= 1024
	} else {
		rbBytes = config.DefaultRingBufferSizeKB * 1024
	}
	rbSize := roundUpPow2(config.ClampUint32(rbBytes))
	if m, ok := spec.Maps["events"]; ok {
		m.MaxEntries = rbSize
	}
	hashSize := config.ClampUint32(config.BPFHashMapSize)
	for name, m := range spec.Maps {
		if m.Type == ebpf.Hash && m.MaxEntries < hashSize {
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
	applyVerifierLogOptions(&opts)

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		logVerifierFailure(err)
		return nil, NewCollectionError(err)
	}

	if threshMap, ok := coll.Maps["alert_thresholds"]; ok && threshMap != nil {
		thresholds := []uint32{
			config.ClampUint32(config.AlertWarnPct),
			config.ClampUint32(config.AlertCritPct),
			config.ClampUint32(config.AlertEmergPct),
		}
		for i, v := range thresholds {
			k := uint32(i)
			val := v
			if err := threshMap.Update(&k, &val, ebpf.UpdateAny); err != nil {
				logger.Warn("Failed to set alert threshold", zap.Int("index", i), zap.Uint32("value", val), zap.Error(err))
			}
		}
	}

	probeGroups, err := probes.AttachProbesByGroup(coll)
	if err != nil {
		coll.Close()
		return nil, err
	}
	var links []link.Link
	for _, ls := range probeGroups {
		links = append(links, ls...)
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
		collection:            coll,
		links:                 links,
		probeGroups:           probeGroups,
		intentionallyDisabled: map[probes.ProbeGroup]struct{}{},
		reader:                rd,
		filter:                filter.NewCgroupFilter(),
		processNameCache:      processCache,
		pathCache:             cache.NewPathCache(),
		resourceMgr:           newResourceMonitorManager(),
	}
	t.useUserspaceCgroupFilter.Store(true)
	t.storeCgroupIDs(map[uint64]struct{}{})

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

// SetCgroups replaces the tracer's entire cgroup filter set with the
// given paths.
func (t *Tracer) SetCgroups(cgroupPaths []string) error {
	if len(cgroupPaths) == 0 {
		t.cgroupWriteMu.Lock()
		t.cgroupPaths = nil
		t.cgroupPath = ""
		t.targetCgroupID.Store(0)
		t.storeCgroupIDs(map[uint64]struct{}{})
		t.filter.SetCgroupPaths(nil)
		if err := t.syncTargetCgroupMap(); err != nil {
			logger.Warn("Failed to clear target_cgroup_ids map", zap.Error(err))
		}
		t.cgroupWriteMu.Unlock()
		t.syncDNSPacketProbes(nil)
		logger.Debug("Detached all cgroups")
		return nil
	}
	return t.attachCgroups(cgroupPaths, true /* replace */)
}

// AttachToCgroup adds cgroupPath to the tracer's filter set and is
// idempotent.
func (t *Tracer) AttachToCgroup(cgroupPath string) error {
	return t.attachCgroups([]string{cgroupPath}, false /* replace */)
}

// AttachToCgroups replaces the tracer's entire cgroup filter set with
// the given list.
func (t *Tracer) AttachToCgroups(cgroupPaths []string) error {
	return t.attachCgroups(cgroupPaths, true /* replace */)
}

// attachCgroups is the shared implementation. When replace=false the
// new cgroups are merged into the existing filter state (engine path);
// when replace=true the existing state is dropped first (session Job
// bulk-attach path).
func (t *Tracer) attachCgroups(cgroupPaths []string, replace bool) error {
	normalized := make([]string, 0, len(cgroupPaths))
	for _, cgroupPath := range cgroupPaths {
		if cgroupPath == "" {
			continue
		}
		containerSubPath := filepath.Join(cgroupPath, "container")
		if _, err := os.Stat(filepath.Join(containerSubPath, "cgroup.procs")); err == nil {
			logger.Debug("Found CRI-O container subfolder, using it for precise cgroup filtering",
				zap.String("parent_path", cgroupPath),
				zap.String("container_path", containerSubPath))
			cgroupPath = containerSubPath
		}
		if filter.NormalizeCgroupPath(cgroupPath) == "" && os.Getenv("PODTRACE_ALLOW_ROOT_CGROUP") != "1" {
			return fmt.Errorf("podtrace: resolved cgroup path %q normalizes to root; refusing to attach (set PODTRACE_ALLOW_ROOT_CGROUP=1 to override)", cgroupPath)
		}
		normalized = append(normalized, cgroupPath)
	}
	if len(normalized) == 0 {
		return fmt.Errorf("no valid cgroup paths provided")
	}

	// Serialize multi-writer access (engine reconciles + the event-loop's
	// auto-disable path) and build a fresh ID map for an atomic publish.
	t.cgroupWriteMu.Lock()
	defer t.cgroupWriteMu.Unlock()

	var allPaths []string
	var newIDs map[uint64]struct{}
	if replace {
		allPaths = normalized
		t.targetCgroupID.Store(0)
		newIDs = make(map[uint64]struct{}, len(normalized))
	} else {
		seen := make(map[string]struct{}, len(t.cgroupPaths)+len(normalized))
		for _, p := range t.cgroupPaths {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			allPaths = append(allPaths, p)
		}
		for _, p := range normalized {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			allPaths = append(allPaths, p)
		}
		newIDs = make(map[uint64]struct{}, len(allPaths))
		for k := range t.loadCgroupIDs() {
			newIDs[k] = struct{}{}
		}
	}

	t.cgroupPaths = allPaths
	if len(allPaths) > 0 {
		t.cgroupPath = allPaths[0]
	}
	t.filter.SetCgroupPaths(allPaths)

	if t.containerPID == 0 {
		for _, cgroupPath := range allPaths {
			if pid := readFirstPIDFromCgroupProcs(cgroupPath); pid != 0 {
				t.containerPID = pid
				break
			}
		}
	}

	if isCgroupV2Base(config.CgroupBasePath) {
		newPaths := normalized
		for _, cgroupPath := range newPaths {
			if cgid, err := getCgroupIDFromPath(cgroupPath); err == nil && cgid != 0 {
				newIDs[cgid] = struct{}{}
				if t.targetCgroupID.Load() == 0 {
					t.targetCgroupID.Store(cgid)
				}
			} else if err != nil {
				logger.Debug("Could not get cgroup ID from path", zap.Error(err), zap.String("cgroup_path", cgroupPath))
			}
			if entries, err := os.ReadDir(cgroupPath); err == nil {
				for _, e := range entries {
					if !e.IsDir() {
						continue
					}
					child := filepath.Join(cgroupPath, e.Name())
					if cgid, err := getCgroupIDFromPath(child); err == nil && cgid != 0 {
						newIDs[cgid] = struct{}{}
					}
				}
			}
		}
		t.storeCgroupIDs(newIDs)
		if err := t.syncTargetCgroupMap(); err != nil {
			logger.Warn("Failed to sync target_cgroup_ids map", zap.Error(err))
		} else if len(newIDs) > 0 {
			logger.Debug("Set target cgroup IDs for in-kernel filtering", zap.Int("count", len(newIDs)))
		}
		if len(newIDs) > 0 && os.Getenv("PODTRACE_DISABLE_USERSPACE_CGROUP_FILTER") == "1" {
			t.useUserspaceCgroupFilter.Store(false)
		}
	} else {
		t.storeCgroupIDs(newIDs)
		logger.Debug("Cgroup v2 not detected, using userspace filtering only", zap.String("cgroup_base", config.CgroupBasePath))
	}
	currentPaths := append([]string(nil), t.cgroupPaths...)
	t.syncDNSPacketProbes(currentPaths)

	if t.resourceMgr != nil {
		t.resourceMgr.reconcile(currentPaths)
	}

	logger.Debug("Attached to cgroups",
		zap.Int("cgroup_count", len(t.cgroupPaths)),
		zap.Uint32("container_pid", t.containerPID),
		zap.Int("target_cgroup_id_count", len(newIDs)),
		zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()),
		zap.Bool("replace", replace))
	return nil
}

func (t *Tracer) syncTargetCgroupMap() error {
	if t.collection == nil || t.collection.Maps == nil {
		return nil
	}
	targetMap, ok := t.collection.Maps["target_cgroup_ids"]
	if !ok || targetMap == nil {
		return nil
	}

	ids := t.loadCgroupIDs()

	if len(ids) == 0 {
		if err := t.setCgroupFilterEnabled(false); err != nil {
			return err
		}
	}

	var key uint64
	var val uint8
	stale := make([]uint64, 0)
	iter := targetMap.Iterate()
	for iter.Next(&key, &val) {
		if _, want := ids[key]; !want {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate target_cgroup_ids: %w", err)
	}
	for _, k := range stale {
		staleKey := k
		if err := targetMap.Delete(&staleKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	one := uint8(1)
	for cgid := range ids {
		cgidCopy := cgid
		if err := targetMap.Update(&cgidCopy, &one, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	if len(ids) > 0 {
		return t.setCgroupFilterEnabled(true)
	}
	return nil
}

// setCgroupFilterEnabled flips the dedicated flag the BPF side consults
// before applying the in-kernel cgroup prefilter.
func (t *Tracer) setCgroupFilterEnabled(enabled bool) error {
	if t.collection == nil || t.collection.Maps == nil {
		return nil
	}
	flagMap, ok := t.collection.Maps["cgroup_filter_enabled"]
	if !ok || flagMap == nil {
		return nil
	}
	var zero uint32
	val := uint32(0)
	if enabled {
		val = 1
	}
	return flagMap.Update(&zero, &val, ebpf.UpdateAny)
}

func readFirstPIDFromCgroupProcs(cgroupPath string) uint32 {
	rel, ok := sysfs.CgroupRelative(cgroupPath)
	if !ok {
		return 0
	}
	data, err := sysfs.CgroupReadFile(filepath.Join(rel, "cgroup.procs"))
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
	return t.SetContainerIDs([]string{containerID})
}

func (t *Tracer) SetContainerIDs(containerIDs []string) error {
	if len(containerIDs) == 0 {
		return fmt.Errorf("no container IDs provided")
	}
	primary := ""
	for _, id := range containerIDs {
		if id != "" {
			primary = id
			break
		}
	}
	if primary == "" {
		return fmt.Errorf("all container IDs are empty")
	}

	t.containerID = primary
	// Each batch is registered under its probe group so the category gate
	// and the management endpoints can detach and re-attach it.
	t.registerGroupLinks(probes.GroupTLS, probes.AttachDNSProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupTLS, probes.AttachSyncProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupDatabase, probes.AttachDBProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupPool, probes.AttachPoolProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupTLS, probes.AttachTLSProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupCache, probes.AttachRedisProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupCache, probes.AttachMemcachedProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupMessaging, probes.AttachKafkaProbesWithPID(t.collection, primary, t.containerPID))
	t.registerGroupLinks(probes.GroupFastCGI, probes.AttachFastCGIProbes(t.collection))
	t.registerGroupLinks(probes.GroupNetwork, probes.AttachGRPCProbes(t.collection))
	return nil
}

func (t *Tracer) Start(ctx context.Context, eventChan chan<- *events.Event) error {
	errorLimiter := newErrorRateLimiter()
	slidingWindow := newSlidingWindow(config.DefaultSlidingWindowSize, config.DefaultSlidingWindowBuckets)
	circuitBreaker := newCircuitBreaker(config.DefaultCircuitBreakerThreshold, config.DefaultCircuitBreakerTimeout)
	stackMap := t.collection.Maps["stack_traces"]

	t.cgroupWriteMu.Lock()
	dnsCgroups := append([]string(nil), t.cgroupPaths...)
	t.cgroupWriteMu.Unlock()
	t.syncDNSPacketProbes(dnsCgroups)

	t.resourceMgr.activate(ctx, eventChan,
		t.collection.Maps["cgroup_limits"],
		t.collection.Maps["cgroup_alerts"],
		t.collection.Maps["cgroup_cpu_quota"])

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

	go t.runDNSTimeoutSweeper(ctx, eventChan)

	if config.ManagementPort > 0 {
		go t.serveManagementAPI(ctx, config.ManagementPort)
	}

	// Shared between the monitoring goroutine and the event-reader
	// goroutine below, so they must be atomic.
	var eventsCollected atomic.Int64
	var eventsFiltered atomic.Int64
	var eventsParsed atomic.Int64
	var filteringDisabled atomic.Bool
	startTime := time.Now()

	logger.Info("Starting event collection",
		zap.String("cgroup_path", t.cgroupPath),
		zap.Uint32("container_pid", t.containerPID),
		zap.Uint64("target_cgroup_id", t.targetCgroupID.Load()),
		zap.Int("target_cgroup_id_count", len(t.loadCgroupIDs())),
		zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()))

	go func() {
		// The ticker must live inside this goroutine: it used to be created
		// in Start() with a deferred Stop(), which fired as soon as Start()
		// returned — the ticker never delivered a tick, leaving the
		// filter-auto-disable fallback and the attachment diagnostics below
		// permanently dead.
		eventCollectionTicker := time.NewTicker(5 * time.Second)
		defer eventCollectionTicker.Stop()
		filterAutoDisableHintLogged := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-eventCollectionTicker.C:
				elapsed := time.Since(startTime)
				if !filteringDisabled.Load() && eventsParsed.Load() > 10 && eventsCollected.Load() == 0 && elapsed > 10*time.Second {
					if config.AllowCgroupFilterAutoDisable() {
						logger.Warn("Events being parsed but all filtered - disabling filtering as fallback",
							zap.Int64("events_parsed", eventsParsed.Load()),
							zap.Int64("events_filtered", eventsFiltered.Load()),
							zap.Int64("events_collected", eventsCollected.Load()),
							zap.Uint64("target_cgroup_id", t.targetCgroupID.Load()),
							zap.String("cgroup_path", t.cgroupPath),
							zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()))
						filteringDisabled.Store(true)
						t.cgroupWriteMu.Lock()
						t.useUserspaceCgroupFilter.Store(false)
						t.targetCgroupID.Store(0)
						t.storeCgroupIDs(map[uint64]struct{}{})
						if err := t.syncTargetCgroupMap(); err == nil {
							logger.Info("Cleared kernel-side cgroup filter")
						}
						t.cgroupWriteMu.Unlock()
					} else if !filterAutoDisableHintLogged {
						filterAutoDisableHintLogged = true
						logger.Warn("Events parsed but all filtered; automatic cgroup filter disable not applied. Set PODTRACE_ALLOW_CGROUP_FILTER_DISABLE=1 to allow clearing cgroup filters as a last resort",
							zap.Int64("events_parsed", eventsParsed.Load()),
							zap.Int64("events_filtered", eventsFiltered.Load()),
							zap.Int64("events_collected", eventsCollected.Load()),
							zap.String("cgroup_path", t.cgroupPath))
					}
				} else if eventsParsed.Load() == 0 && elapsed > 15*time.Second {
					logger.Warn("No events parsed from ring buffer after 15 seconds - check eBPF program attachment",
						zap.Uint64("target_cgroup_id", t.targetCgroupID.Load()),
						zap.String("cgroup_path", t.cgroupPath),
						zap.Duration("elapsed", elapsed),
						zap.Int("links_attached", t.linkCount()))
					logger.Warn("If running in a container (e.g. DaemonSet), ensure host /sys/fs/cgroup and /proc are mounted and PODTRACE_CGROUP_BASE / PODTRACE_PROC_BASE point at them; see installation doc 'Running as a DaemonSet'")
				} else if eventsCollected.Load() == 0 && eventsParsed.Load() > 0 && elapsed > 10*time.Second {
					logger.Warn("Events parsed but none collected - filtering may be too strict",
						zap.Int64("events_parsed", eventsParsed.Load()),
						zap.Int64("events_filtered", eventsFiltered.Load()),
						zap.Uint64("target_cgroup_id", t.targetCgroupID.Load()),
						zap.String("cgroup_path", t.cgroupPath),
						zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()),
						zap.Duration("elapsed", elapsed))
					if t.useUserspaceCgroupFilter.Load() {
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
				eventsParsed.Add(1)
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

				if isLikelyTransientComm(event.ProcessName) {
					resolved := false
					if data, err := procfs.ReadFile(fmt.Sprintf("%d/comm", event.PID)); err == nil {
						real := strings.TrimSpace(string(data))
						if real != "" && !isLikelyTransientComm(real) {
							event.ProcessName = validation.SanitizeProcessName(real)
							resolved = true
						}
					}
					if !resolved {
						event.ProcessName = "runc-bootstrap[" + event.ProcessName + "]"
					}
				}

				cache.SnapshotCPUTime(event.PID)

				if t.piiRedactor != nil {
					t.piiRedactor.Redact(event)
				}
				if t.cpAnalyzer != nil {
					t.cpAnalyzer.Feed(event)
				}

				if event.Error != 0 {
					metricsexporter.RecordError(event.TypeString(), event.Error)
				}

				allowed := true
				cgroupIDs := t.loadCgroupIDs()
				if filteringDisabled.Load() {
					// Fallback mode: allow all events
					allowed = true
				} else if len(cgroupIDs) > 0 && event.CgroupID != 0 {
					_, allowed = cgroupIDs[event.CgroupID]
					if !allowed {
						// Log first few mismatches for debugging, then throttle
						if eventsFiltered.Add(1) <= 5 || time.Now().Unix()%10 == 0 {
							logger.Debug("Event filtered by cgroup ID mismatch",
								zap.Uint64("event_cgroup_id", event.CgroupID),
								zap.Int("target_cgroup_id_count", len(cgroupIDs)),
								zap.Uint32("pid", event.PID),
								zap.String("process", event.ProcessName))
						}
					}
				} else if t.useUserspaceCgroupFilter.Load() {
					allowed = t.filter.IsPIDInCgroup(event.PID)
					if !allowed {
						if eventsFiltered.Add(1) <= 5 || time.Now().Unix()%10 == 0 {
							logger.Debug("Event filtered by userspace PID cgroup check",
								zap.Uint32("pid", event.PID),
								zap.String("process", event.ProcessName),
								zap.String("cgroup_path", t.cgroupPath))
						}
					}
				} else {
					if eventsParsed.Load() <= 5 {
						logger.Debug("No cgroup filtering active, allowing all events",
							zap.Uint64("event_cgroup_id", event.CgroupID),
							zap.Uint64("target_cgroup_id", t.targetCgroupID.Load()),
							zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()))
					}
				}

				if allowed {
					select {
					case <-ctx.Done():
						parser.PutEvent(event)
						return
					case eventChan <- event:
						if eventsCollected.Add(1) <= 5 {
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

	t.probeGroupsMu.Lock()
	closing := t.links
	t.links = nil
	t.probeGroups = map[probes.ProbeGroup][]link.Link{}
	for _, ls := range t.dnsPacketLinks {
		closing = append(closing, ls...)
	}
	t.dnsPacketLinks = nil
	t.probeGroupsMu.Unlock()
	for _, l := range closing {
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

	if t.resourceMgr != nil {
		t.resourceMgr.stopAll()
	}

	return nil
}

// isLikelyTransientComm flags single-character or single-digit comm values
// that the kernel sets transiently during exec — most commonly runc's
// memfd-based re-exec where comm becomes the FD basename ("6") before runc
// calls prctl(PR_SET_NAME) to rename itself. Re-reading /proc/<pid>/comm a
// few milliseconds later (when our userspace processes the event) returns
// the post-prctl name.
func isLikelyTransientComm(name string) bool {
	if len(name) != 1 {
		return false
	}
	c := name[0]
	return c >= '0' && c <= '9'
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

	pidStr := fmt.Sprintf("%d", pid)

	if cmdline, err := procfs.ReadFile(pidStr + "/cmdline"); err == nil {
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			name = parts[0]
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/stat"); err == nil {
			statStr := string(data)
			start := strings.Index(statStr, "(")
			end := strings.LastIndex(statStr, ")")
			if start >= 0 && end > start {
				name = statStr[start+1 : end]
			}
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/comm"); err == nil {
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

// SetEnabledCategories disables probe groups whose CRD-filter categories
// are absent from `categories`. This is the kernel-side counterpart to
// the Router's per-event userspace filtering — when no CR on this node
// asks for a category, the corresponding kprobes can stay un-attached,
// saving the per-event kernel overhead.
//
// Semantics:
//
//   - `categories == nil` is a sentinel: "do not gate anything" — the
//     bootstrap default before the agent has observed any CRs. Calling
//     with nil is a no-op so a freshly-started agent does not strip the
//     default attach set out from under in-flight events.
//   - An empty (non-nil) slice means "no CR needs any category here",
//     and disables every gateable group.
//   - Currently this is detach-only: groups newly absent from the
//     active set are closed; groups newly present in the active set
//     but previously closed are NOT re-attached. A warning is logged
//     so operators know to restart the agent to pick up the new
//     category. Hot re-attach is a separate change because the
//     attach-while-events-flow race is non-trivial.
//
// SetEnabledCategories is safe to call concurrently with event
// processing — only the probeGroups map is mutated, under its mutex.
func (t *Tracer) SetEnabledCategories(categories []string) error {
	if categories == nil {
		return nil
	}
	wanted := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		wanted[c] = struct{}{}
	}

	t.probeGroupsMu.Lock()
	active := make([]probes.ProbeGroup, 0, len(t.probeGroups))
	for g := range t.probeGroups {
		active = append(active, g)
	}
	t.probeGroupsMu.Unlock()

	for _, g := range active {
		if probeGroupNeededBy(g, wanted) {
			continue
		}
		if err := t.DisableProbeGroup(g); err != nil {
			logger.Warn("SetEnabledCategories: disable failed",
				zap.String("group", string(g)), zap.Error(err))
			continue
		}
		t.probeGroupsMu.Lock()
		if t.intentionallyDisabled == nil {
			t.intentionallyDisabled = map[probes.ProbeGroup]struct{}{}
		}
		t.intentionallyDisabled[g] = struct{}{}
		t.probeGroupsMu.Unlock()
	}

	for c := range wanted {
		needs := groupsNeededFor(c)
		for _, g := range needs {
			t.probeGroupsMu.Lock()
			_, disabled := t.intentionallyDisabled[g]
			t.probeGroupsMu.Unlock()
			if !disabled {
				continue
			}
			if err := t.EnableProbeGroup(g); err != nil {
				t.probeGroupsMu.Lock()
				if t.detachWarned == nil {
					t.detachWarned = map[probes.ProbeGroup]struct{}{}
				}
				_, warned := t.detachWarned[g]
				if !warned {
					t.detachWarned[g] = struct{}{}
				}
				t.probeGroupsMu.Unlock()
				if !warned {
					logger.Warn("SetEnabledCategories: category needs a detached probe group that could not be re-attached (events in this group are not captured until the agent restarts; common cause: tracefs/debugfs not mounted into the agent)",
						zap.String("category", c), zap.String("group", string(g)), zap.Error(err))
				}
			}
		}
	}
	return nil
}

// EnableProbeGroup re-attaches a probe group that was previously disabled
// by SetEnabledCategories.
func (t *Tracer) EnableProbeGroup(g probes.ProbeGroup) error {
	t.probeGroupsMu.Lock()
	if existing, ok := t.probeGroups[g]; ok && len(existing) > 0 {
		t.probeGroupsMu.Unlock()
		return nil
	}
	coll := t.collection
	t.probeGroupsMu.Unlock()

	if coll == nil {
		return fmt.Errorf("no eBPF collection available to re-attach group %q", g)
	}

	newLinks, err := probes.AttachProbeGroup(coll, g)
	if err != nil {
		return err
	}
	// Groups with container-scoped uprobes (TLS, cache, FastCGI, ...) have
	// nothing in the kprobe/tracepoint tables AttachProbeGroup walks; they
	// are re-attached from the most recent SetContainerIDs target.
	newLinks = append(newLinks, t.attachGroupUprobes(g)...)

	t.probeGroupsMu.Lock()
	t.probeGroups[g] = append(t.probeGroups[g], newLinks...)
	t.links = append(t.links, newLinks...)
	delete(t.intentionallyDisabled, g)
	delete(t.detachWarned, g)
	t.probeGroupsMu.Unlock()

	logger.Info("Probe group re-attached", zap.String("group", string(g)), zap.Int("links", len(newLinks)))
	return nil
}

// probeGroupNeededBy reports whether a group should stay attached
// given the set of categories currently desired by some active CR.
func probeGroupNeededBy(g probes.ProbeGroup, wanted map[string]struct{}) bool {
	needs, gated := groupCategoryNeeds[g]
	if !gated {
		return true // not gateable by category
	}
	for _, c := range needs {
		if _, ok := wanted[c]; ok {
			return true
		}
	}
	return false
}

// groupsNeededFor returns the probe groups required to surface a
// given CRD category.
func groupsNeededFor(category string) []probes.ProbeGroup {
	var out []probes.ProbeGroup
	for g, needs := range groupCategoryNeeds {
		for _, c := range needs {
			if c == category {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// groupCategoryNeeds maps each probe group to the CRD filter
// categories that require it.
var groupCategoryNeeds = map[probes.ProbeGroup][]string{
	probes.GroupNetwork:    {"net"},
	probes.GroupFileSystem: {"fs"},
	probes.GroupCPU:        {"cpu", "proc"},
	probes.GroupMemory:     {"proc"},
	probes.GroupFastCGI:    {"net"},
	probes.GroupTLS:        {"dns", "cpu", "net"},
}

// DisableProbeGroup closes all links associated with the given group.
func (t *Tracer) DisableProbeGroup(g probes.ProbeGroup) error {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	ls, ok := t.probeGroups[g]
	if !ok || len(ls) == 0 {
		return nil
	}
	closed := make(map[link.Link]struct{}, len(ls))
	for _, l := range ls {
		_ = l.Close()
		closed[l] = struct{}{}
	}
	// Drop the closed links from the flat registry too: leaving them in
	// meant Stop() double-closed them and repeated disable/enable cycles
	// grew t.links with dead handles indefinitely.
	kept := t.links[:0]
	for _, l := range t.links {
		if _, isClosed := closed[l]; !isClosed {
			kept = append(kept, l)
		}
	}
	t.links = kept
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

	if t.profilingCtrl != nil {
		mux.HandleFunc("/profile/start", t.profilingCtrl.HTTPStart)
		mux.HandleFunc("/profile/status", t.profilingCtrl.HTTPStatus)
		mux.HandleFunc("/profile/result", t.profilingCtrl.HTTPResult)
		logger.Info("Profiling management endpoints registered",
			zap.Int("port", port))
	}

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
