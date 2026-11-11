package resource

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/safeconv"
	"github.com/gma1k/podtrace/internal/sysfs"
)

const (
	ResourceCPU    = 0
	ResourceMemory = 1
	ResourceIO     = 2
)

const (
	AlertNone      = 0
	AlertWarning   = 1
	AlertCritical  = 2
	AlertEmergency = 3
)

type ResourceLimit struct {
	LimitBytes   uint64
	UsageBytes   uint64
	LastUpdateNS uint64
	ResourceType uint32
}

type bpfLimitMap interface {
	Put(key, value interface{}) error
	Delete(key interface{}) error
}

type limitMapValue struct {
	LimitBytes   uint64
	UsageBytes   uint64
	LastUpdateNS uint64
	ResourceType uint32
	_            [4]byte
}

// resourceMapKey mirrors struct resource_key in bpf/maps.h. Keying the
// BPF maps by cgroup inode alone made CPU, memory, and IO entries
// clobber each other — the surviving entry depended on Go map iteration
// order, so the kernel-visible limit and alert level flapped between
// resource types on every sync.
type resourceMapKey struct {
	CgroupID     uint64
	ResourceType uint32
	_            [4]byte
}

// resourceSample is one (cumulative usage, wall clock) observation, kept so
// CPU and IO utilization can be computed as RATES between ticks.
type resourceSample struct {
	usage  uint64
	wallNS uint64
}

type ResourceMonitor struct {
	cgroupPath    string
	cgroupInode   uint64
	limitsMap     bpfLimitMap
	alertsMap     bpfLimitMap
	eventChan     chan<- *events.Event
	mu            sync.RWMutex
	limits        map[uint32]*ResourceLimit
	checkInterval time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup

	identityMu sync.RWMutex
	namespace  string
	podName    string

	cpuQuotaMicros  uint64
	cpuPeriodMicros uint64
	previousSamples map[uint32]resourceSample

	ioLimits        map[ioChannel]uint64
	ioPrevious      map[ioChannel]uint64
	ioPreviousNS    uint64
	ioUtilization   float64
	ioUtilizationOK bool

	publishedTypes map[uint32]struct{}

	cpuQuotaMap      bpfLimitMap
	cpuAlertsReadMap bpfAlertReadMap
	cpuSamplerOn     bool
	cpuQuotaInBPF    bool
}

// ioChannel is one direction of one block device. cgroup IO limits are set
// per device and per direction, so utilization is only meaningful against
// the limit of the same channel.
type ioChannel struct {
	device string
	write  bool
}

// limitSet is one reading of a cgroup's configured limits.
type limitSet struct {
	cpuQuotaMicros  uint64
	cpuPeriodMicros uint64
	memoryBytes     uint64
	io              map[ioChannel]uint64
}

// knownResourceTypes are the resource types a monitor can publish, released
// from the BPF maps when the monitor stops.
var knownResourceTypes = []uint32{ResourceCPU, ResourceMemory, ResourceIO}

// unlimitedMemoryThreshold: cgroup v1 reports "no limit" as PAGE_COUNTER_MAX
// pages (0x7FFFFFFFFFFFF000 with 4K pages), not "max". No real limit is near
// 2^62 bytes.
const unlimitedMemoryThreshold = uint64(1) << 62

type bpfAlertReadMap interface {
	Lookup(key, valueOut interface{}) error
}

func NewResourceMonitor(cgroupPath string, limitsMap, alertsMap *ebpf.Map, eventChan chan<- *events.Event, namespace string) (*ResourceMonitor, error) {
	inode, err := getCgroupInode(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get cgroup inode: %w", err)
	}

	rm := &ResourceMonitor{
		cgroupPath:      cgroupPath,
		cgroupInode:     inode,
		eventChan:       eventChan,
		limits:          make(map[uint32]*ResourceLimit),
		previousSamples: make(map[uint32]resourceSample),
		publishedTypes:  make(map[uint32]struct{}),
		checkInterval:   config.ResourceMonitorInterval,
		stopCh:          make(chan struct{}),
		namespace:       namespace,
	}
	if limitsMap != nil {
		rm.limitsMap = limitsMap
	}
	if alertsMap != nil {
		rm.alertsMap = alertsMap
	}

	if err := rm.readLimits(); err != nil {
		logger.Warn("Failed to read initial resource limits", zap.Error(err), zap.String("cgroup_path", cgroupPath))
	} else {
		logger.Debug("Resource limits read successfully", zap.Int("num_limits", len(rm.limits)))
		for rType, limit := range rm.limits {
			logger.Debug("Resource limit", zap.Uint32("type", rType), zap.Uint64("limit", limit.LimitBytes))
		}
	}

	return rm, nil
}

// SetPodIdentity records the Kubernetes pod that owns the monitored cgroup so
// alerts name the pod (and can become trigger Events) instead of the cgroup.
func (rm *ResourceMonitor) SetPodIdentity(podName, namespace string) {
	rm.identityMu.Lock()
	defer rm.identityMu.Unlock()
	rm.podName = podName
	rm.namespace = namespace
}

// alertSubject returns the PodName/Namespace an alert carries. Without a
// resolved pod the cgroup path stays the subject only when no namespace is
// known either, so it keeps alerts for distinct cgroups apart but can never
// become the involved object of a Kubernetes Event.
func (rm *ResourceMonitor) alertSubject() (podName, namespace string) {
	rm.identityMu.RLock()
	defer rm.identityMu.RUnlock()
	if rm.podName != "" || rm.namespace != "" {
		return rm.podName, rm.namespace
	}
	return rm.cgroupPath, ""
}

func (rm *ResourceMonitor) metricsNamespace() string {
	rm.identityMu.RLock()
	defer rm.identityMu.RUnlock()
	return rm.namespace
}

func (rm *ResourceMonitor) Start(ctx context.Context) {
	rm.wg.Add(1)
	go rm.monitorLoop(ctx)
}

// Stop ends the monitor loop and removes every entry the monitor wrote to
// the shared BPF maps. The maps are plain hashes shared by all monitors, so
// entries left behind by departed cgroups would fill them under pod churn.
func (rm *ResourceMonitor) Stop() {
	close(rm.stopCh)
	rm.wg.Wait()
	rm.releaseBPFEntries()
}

// releaseBPFEntries deletes the CPU quota first so the in-kernel sampler
// stops writing alerts for this cgroup before its alert keys are removed.
func (rm *ResourceMonitor) releaseBPFEntries() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.cpuQuotaMap != nil {
		logMapDelete(rm.cpuQuotaMap, rm.cgroupInode, "cgroup_cpu_quota")
		rm.cpuQuotaInBPF = false
	}
	for _, resourceType := range knownResourceTypes {
		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: resourceType}
		if rm.limitsMap != nil {
			logMapDelete(rm.limitsMap, key, "cgroup_limits")
		}
		if rm.alertsMap != nil {
			logMapDelete(rm.alertsMap, key, "cgroup_alerts")
		}
	}
	clear(rm.publishedTypes)
}

func logMapDelete(m bpfLimitMap, key interface{}, mapName string) {
	if err := m.Delete(key); err != nil && !isBenignMapDeleteError(err) {
		logger.Debug("Failed to delete resource monitor map entry", zap.String("map", mapName), zap.Error(err))
	}
}

func (rm *ResourceMonitor) monitorLoop(ctx context.Context) {
	defer rm.wg.Done()

	ticker := time.NewTicker(rm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopCh:
			return
		case <-ticker.C:
			rm.refreshLimits()
			if err := rm.updateResourceUsage(); err != nil {
				logger.Debug("Failed to update resource usage", zap.Error(err))
			}
			rm.checkAlerts()
			rm.checkBPFCPUAlerts()
		}
	}
}

// readLimits reads the configured limits and publishes them to BPF.
func (rm *ResourceMonitor) readLimits() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if isCgroupV2(rm.cgroupPath) {
		return rm.readLimitsV2()
	}
	return rm.readLimitsV1()
}

// refreshLimits re-reads the limits every tick so an in-place pod resize, or
// a limit added or removed, is picked up without restarting the monitor.
func (rm *ResourceMonitor) refreshLimits() {
	rm.mu.Lock()
	quotaChanged := rm.applyLimitSet(rm.readLimitSet())
	sampler := rm.cpuQuotaMap != nil
	rm.mu.Unlock()

	if quotaChanged && sampler {
		if err := rm.syncCPUQuota(); err != nil {
			logger.Warn("Failed to sync CPU quota to BPF sampler", zap.Error(err))
		}
	}
}

func (rm *ResourceMonitor) readLimitsV2() error {
	rm.applyLimitSet(rm.readLimitSetV2())
	return rm.syncToBPF()
}

func (rm *ResourceMonitor) readLimitsV1() error {
	rm.applyLimitSet(rm.readLimitSetV1())
	return rm.syncToBPF()
}

func (rm *ResourceMonitor) readLimitSet() limitSet {
	if isCgroupV2(rm.cgroupPath) {
		return rm.readLimitSetV2()
	}
	return rm.readLimitSetV1()
}

func (rm *ResourceMonitor) readLimitSetV2() limitSet {
	var set limitSet
	if cpuMax, err := readCgroupFile(filepath.Join(rm.cgroupPath, "cpu.max")); err == nil {
		quota, period, unlimited := parseCPUMax(cpuMax)
		if !unlimited && quota > 0 && period > 0 {
			set.cpuQuotaMicros = quota
			set.cpuPeriodMicros = period
		}
	}
	if memMax, err := readCgroupFile(filepath.Join(rm.cgroupPath, "memory.max")); err == nil {
		set.memoryBytes = finiteMemoryLimit(parseMemoryMax(memMax))
	}
	if ioMax, err := readCgroupFile(filepath.Join(rm.cgroupPath, "io.max")); err == nil {
		set.io = parseIOMaxChannels(ioMax)
	}
	return set
}

// cgroup v1 controller mount directory candidates, relative to
// config.CgroupBasePath. Each controller is its own hierarchy; cpu and cpuacct
// are usually co-mounted ("cpu,cpuacct") but may be split, so try both forms.
var (
	cgroupV1CPUDirs     = []string{"cpu,cpuacct", "cpuacct,cpu", "cpu"}
	cgroupV1CPUAcctDirs = []string{"cpu,cpuacct", "cpuacct,cpu", "cpuacct"}
	cgroupV1MemoryDirs  = []string{"memory"}
	cgroupV1BlkioDirs   = []string{"blkio"}
)

// cgroupV1Subpath returns the pod's cgroup path relative to a v1 controller
// root: the discovered path with the base and the leading controller segment
// stripped. For "/sys/fs/cgroup/cpu,cpuacct/kubepods/pod123" it returns
// "kubepods/pod123", which then reattaches under any controller hierarchy.
func cgroupV1Subpath(cgroupPath string) (string, bool) {
	rel, ok := sysfs.CgroupRelative(cgroupPath)
	if !ok || rel == "." {
		return "", false
	}
	slash := strings.IndexByte(rel, '/')
	if slash < 0 {
		return "", false
	}
	return rel[slash+1:], true
}

// readV1ControllerFile reads a cgroup v1 file from the first controller mount
// that has it: <base>/<controller>/<subpath>/<file>. Unlike v2, the controller
// is a path PREFIX (a separate hierarchy), not a subdirectory of the pod path.
func readV1ControllerFile(controllers []string, subpath, file string) (string, error) {
	var lastErr error
	for _, ctrl := range controllers {
		content, err := readCgroupFile(filepath.Join(config.CgroupBasePath, ctrl, subpath, file))
		if err == nil {
			return content, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no controller mount found for %s among %v", file, controllers)
	}
	return "", lastErr
}

func (rm *ResourceMonitor) readLimitSetV1() limitSet {
	var set limitSet
	subpath, ok := cgroupV1Subpath(rm.cgroupPath)
	if !ok {
		logger.Debug("cgroup v1: cannot derive controller subpath from cgroup path",
			zap.String("cgroup_path", rm.cgroupPath))
		return set
	}

	cpuQuota, _ := readV1ControllerFile(cgroupV1CPUDirs, subpath, "cpu.cfs_quota_us")
	cpuPeriod, _ := readV1ControllerFile(cgroupV1CPUDirs, subpath, "cpu.cfs_period_us")
	if cpuQuota != "" && cpuPeriod != "" {
		quota, _ := strconv.ParseUint(strings.TrimSpace(cpuQuota), 10, 64)
		period, _ := strconv.ParseUint(strings.TrimSpace(cpuPeriod), 10, 64)
		if quota > 0 && period > 0 {
			set.cpuQuotaMicros = quota
			set.cpuPeriodMicros = period
		}
	}

	if memLimit, err := readV1ControllerFile(cgroupV1MemoryDirs, subpath, "memory.limit_in_bytes"); err == nil {
		set.memoryBytes = finiteMemoryLimit(parseMemoryMax(memLimit))
	}

	ioRead, _ := readV1ControllerFile(cgroupV1BlkioDirs, subpath, "blkio.throttle.read_bps_device")
	ioWrite, _ := readV1ControllerFile(cgroupV1BlkioDirs, subpath, "blkio.throttle.write_bps_device")
	set.io = make(map[ioChannel]uint64)
	for device, bps := range parseBlkioThrottleDevices(ioRead) {
		set.io[ioChannel{device: device}] = bps
	}
	for device, bps := range parseBlkioThrottleDevices(ioWrite) {
		set.io[ioChannel{device: device, write: true}] = bps
	}
	return set
}

// finiteMemoryLimit maps the "no limit" encodings of both cgroup versions
// to 0.
func finiteMemoryLimit(limit uint64) uint64 {
	if limit >= unlimitedMemoryThreshold {
		return 0
	}
	return limit
}

// applyLimitSet makes set the monitor's limits, keeping the usage already
// sampled for a resource whose limit is unchanged or only resized, and
// reports whether the CPU quota changed. Caller holds rm.mu.
func (rm *ResourceMonitor) applyLimitSet(set limitSet) bool {
	quotaChanged := set.cpuQuotaMicros != rm.cpuQuotaMicros || set.cpuPeriodMicros != rm.cpuPeriodMicros
	rm.cpuQuotaMicros = set.cpuQuotaMicros
	rm.cpuPeriodMicros = set.cpuPeriodMicros

	rm.ioLimits = nil
	var ioLimit uint64
	for ch, bps := range set.io {
		if bps == 0 {
			continue
		}
		if rm.ioLimits == nil {
			rm.ioLimits = make(map[ioChannel]uint64)
		}
		rm.ioLimits[ch] = bps
		ioLimit = max(ioLimit, bps)
	}
	if ioLimit == 0 {
		rm.ioPrevious = nil
		rm.ioPreviousNS = 0
		rm.ioUtilizationOK = false
	}

	var cpuLimit uint64
	if set.cpuQuotaMicros > 0 && set.cpuPeriodMicros > 0 {
		cpuLimit = set.cpuQuotaMicros
	}
	rm.setLimit(ResourceCPU, cpuLimit)
	rm.setLimit(ResourceMemory, set.memoryBytes)
	rm.setLimit(ResourceIO, ioLimit)
	return quotaChanged
}

func (rm *ResourceMonitor) setLimit(resourceType uint32, limitBytes uint64) {
	existing, ok := rm.limits[resourceType]
	if limitBytes == 0 {
		if ok {
			delete(rm.limits, resourceType)
			delete(rm.previousSamples, resourceType)
			logger.Debug("Resource limit removed", zap.String("cgroup_path", rm.cgroupPath), zap.Uint32("type", resourceType))
		}
		return
	}
	if ok {
		if existing.LimitBytes != limitBytes {
			logger.Debug("Resource limit changed", zap.String("cgroup_path", rm.cgroupPath),
				zap.Uint32("type", resourceType), zap.Uint64("from", existing.LimitBytes), zap.Uint64("to", limitBytes))
			existing.LimitBytes = limitBytes
		}
		return
	}
	limit := &ResourceLimit{LimitBytes: limitBytes, ResourceType: resourceType}
	if resourceType != ResourceCPU {
		limit.LastUpdateNS = uint64(time.Now().UnixNano())
	}
	rm.limits[resourceType] = limit
	logger.Debug("Resource limit read", zap.String("cgroup_path", rm.cgroupPath),
		zap.Uint32("type", resourceType), zap.Uint64("limit", limitBytes))
}

func (rm *ResourceMonitor) updateResourceUsage() error {
	rm.mu.Lock()
	if limit, ok := rm.limits[ResourceCPU]; ok && limit.LastUpdateNS != 0 {
		rm.previousSamples[ResourceCPU] = resourceSample{usage: limit.UsageBytes, wallNS: limit.LastUpdateNS}
	}
	defer rm.mu.Unlock()

	if isCgroupV2(rm.cgroupPath) {
		return rm.updateUsageV2()
	}
	return rm.updateUsageV1()
}

func (rm *ResourceMonitor) updateUsageV2() error {
	cpuStat, err := readCgroupFile(filepath.Join(rm.cgroupPath, "cpu.stat"))
	if err == nil {
		usage := parseCPUStat(cpuStat)
		if limit, ok := rm.limits[ResourceCPU]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	memCurrent, err := readCgroupFile(filepath.Join(rm.cgroupPath, "memory.current"))
	if err == nil {
		usage := parseMemoryMax(memCurrent)
		if limit, ok := rm.limits[ResourceMemory]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	if _, ok := rm.limits[ResourceIO]; ok {
		if ioStat, err := readCgroupFile(filepath.Join(rm.cgroupPath, "io.stat")); err == nil {
			rm.recordIOSample(parseIOStatChannels(ioStat), uint64(time.Now().UnixNano()))
		}
	}

	return rm.syncToBPF()
}

func (rm *ResourceMonitor) updateUsageV1() error {
	subpath, ok := cgroupV1Subpath(rm.cgroupPath)
	if !ok {
		return rm.syncToBPF()
	}

	cpuUsage, err := readV1ControllerFile(cgroupV1CPUAcctDirs, subpath, "cpuacct.usage")
	if err == nil {
		usage, _ := strconv.ParseUint(strings.TrimSpace(cpuUsage), 10, 64)
		if limit, ok := rm.limits[ResourceCPU]; ok {
			limit.UsageBytes = usage / 1000 // Convert nanoseconds to microseconds
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	memUsage, err := readV1ControllerFile(cgroupV1MemoryDirs, subpath, "memory.usage_in_bytes")
	if err == nil {
		usage := parseMemoryMax(memUsage)
		if limit, ok := rm.limits[ResourceMemory]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	if _, ok := rm.limits[ResourceIO]; ok {
		if ioBytes, err := readV1ControllerFile(cgroupV1BlkioDirs, subpath, "blkio.io_service_bytes"); err == nil {
			rm.recordIOSample(parseBlkioServiceChannels(ioBytes), uint64(time.Now().UnixNano()))
		}
	}

	return rm.syncToBPF()
}

// recordIOSample stores the cumulative per-channel byte counters and derives
// IO utilization as the busiest limited channel's rate against that
// channel's own limit. Caller holds rm.mu.
func (rm *ResourceMonitor) recordIOSample(usage map[ioChannel]uint64, nowNS uint64) {
	if limit, ok := rm.limits[ResourceIO]; ok {
		var total uint64
		for _, b := range usage {
			total += b
		}
		limit.UsageBytes = total
		limit.LastUpdateNS = nowNS
	}
	rm.ioUtilization, rm.ioUtilizationOK = 0, false
	if rm.ioPrevious != nil && nowNS > rm.ioPreviousNS {
		rm.ioUtilization, rm.ioUtilizationOK = ioChannelUtilization(rm.ioLimits, rm.ioPrevious, usage, nowNS-rm.ioPreviousNS)
	}
	rm.ioPrevious = usage
	rm.ioPreviousNS = nowNS
}

// ioChannelUtilization returns the highest rate/limit percentage over the
// limited channels. A channel absent from io.stat has moved no bytes.
func ioChannelUtilization(limits, previous, current map[ioChannel]uint64, elapsedNS uint64) (float64, bool) {
	seconds := float64(elapsedNS) / 1e9
	busiest, ok := 0.0, false
	for ch, limit := range limits {
		before, after := previous[ch], current[ch]
		if limit == 0 || after < before {
			continue
		}
		percent := float64(after-before) / seconds / float64(limit) * 100
		if !ok || percent > busiest {
			busiest, ok = percent, true
		}
	}
	return busiest, ok
}

func (rm *ResourceMonitor) syncToBPF() error {
	rm.unpublishRemovedTypes()
	if rm.publishedTypes == nil {
		rm.publishedTypes = make(map[uint32]struct{})
	}
	for resourceType := range rm.limits {
		rm.publishedTypes[resourceType] = struct{}{}
	}
	if rm.limitsMap == nil {
		return nil
	}

	for resourceType, limit := range rm.limits {
		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: resourceType}
		value := limitMapValue{
			LimitBytes:   limit.LimitBytes,
			UsageBytes:   limit.UsageBytes,
			LastUpdateNS: limit.LastUpdateNS,
			ResourceType: resourceType,
		}

		if err := rm.limitsMap.Put(key, value); err != nil {
			logger.Warn("Failed to update BPF map",
				zap.Uint64("cgroup_inode", rm.cgroupInode),
				zap.Uint32("resource_type", resourceType),
				zap.Error(err))
		}
	}

	return nil
}

// unpublishRemovedTypes deletes the limit and alert entries of resource
// types whose limit was removed since they were published. Caller holds
// rm.mu.
func (rm *ResourceMonitor) unpublishRemovedTypes() {
	for resourceType := range rm.publishedTypes {
		if _, ok := rm.limits[resourceType]; ok {
			continue
		}
		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: resourceType}
		if rm.limitsMap != nil {
			logMapDelete(rm.limitsMap, key, "cgroup_limits")
		}
		if rm.alertsMap != nil {
			logMapDelete(rm.alertsMap, key, "cgroup_alerts")
		}
		delete(rm.publishedTypes, resourceType)
	}
}

func isBenignMapDeleteError(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}

// utilizationPercent returns the 0-100 utilization for one resource.
func (rm *ResourceMonitor) utilizationPercent(resourceType uint32, limit *ResourceLimit) (uint64, bool) {
	clamp := func(v float64) (uint64, bool) {
		if v < 0 {
			return 0, false
		}
		if v > 100 {
			return 100, true
		}
		return uint64(v), true
	}

	switch resourceType {
	case ResourceMemory:
		return clamp(float64(limit.UsageBytes) * 100 / float64(limit.LimitBytes))

	case ResourceCPU:
		if rm.cpuQuotaMicros == 0 || rm.cpuPeriodMicros == 0 {
			return 0, false
		}
		previous, ok := rm.previousSamples[ResourceCPU]
		if !ok || limit.LastUpdateNS <= previous.wallNS || limit.UsageBytes < previous.usage {
			return 0, false
		}
		usedMicros := float64(limit.UsageBytes - previous.usage)
		wallMicros := float64(limit.LastUpdateNS-previous.wallNS) / 1000
		if wallMicros <= 0 {
			return 0, false
		}
		allowedCPUs := float64(rm.cpuQuotaMicros) / float64(rm.cpuPeriodMicros)
		return clamp(usedMicros / wallMicros / allowedCPUs * 100)

	case ResourceIO:
		if !rm.ioUtilizationOK {
			return 0, false
		}
		return clamp(rm.ioUtilization)

	default:
		return clamp(float64(limit.UsageBytes) * 100 / float64(limit.LimitBytes))
	}
}

func (rm *ResourceMonitor) checkAlerts() {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.alertsMap == nil {
		return
	}

	resourceTypeLabels := map[uint32]string{
		ResourceCPU:    "cpu",
		ResourceMemory: "memory",
		ResourceIO:     "io",
	}

	for resourceType, limit := range rm.limits {
		if limit.LimitBytes == 0 || limit.LimitBytes == ^uint64(0) {
			continue
		}

		if resourceType == ResourceCPU && rm.cpuSamplerOn && rm.cpuQuotaInBPF {
			continue
		}

		utilization, ok := rm.utilizationPercent(resourceType, limit)
		if !ok {
			continue
		}
		utilizationUint32 := safeconv.Uint64ToUint32(utilization)

		var alertLevel uint32
		switch {
		case utilizationUint32 >= safeconv.IntToUint32(config.AlertEmergPct):
			alertLevel = AlertEmergency
		case utilizationUint32 >= safeconv.IntToUint32(config.AlertCritPct):
			alertLevel = AlertCritical
		case utilizationUint32 >= safeconv.IntToUint32(config.AlertWarnPct):
			alertLevel = AlertWarning
		default:
			alertLevel = AlertNone
		}

		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: resourceType}
		if alertLevel > 0 {
			if err := rm.alertsMap.Put(key, alertLevel); err != nil {
				logger.Warn("Failed to update alert map", zap.Error(err))
			}
		} else {
			if err := rm.alertsMap.Delete(key); err != nil && !isBenignMapDeleteError(err) {
				logger.Warn("Failed to delete alert from map", zap.Error(err))
			}
		}

		resourceTypeLabel := resourceTypeLabels[resourceType]
		if resourceTypeLabel == "" {
			resourceTypeLabel = fmt.Sprintf("resource_%d", resourceType)
		}

		utilizationPercent := float64(utilizationUint32)
		metricsexporter.ExportResourceMetrics(
			resourceTypeLabel,
			rm.metricsNamespace(),
			limit.LimitBytes,
			limit.UsageBytes,
			utilizationPercent,
			alertLevel,
		)

		if alertLevel > AlertNone {
			manager := alerting.GetGlobalManager()
			if manager != nil {
				severity := alerting.MapResourceAlertLevel(alertLevel)
				title := fmt.Sprintf("Resource Limit %s: %s", severity, resourceTypeLabel)
				message := fmt.Sprintf("%s utilization: %d%% (limit: %d bytes, usage: %d bytes)",
					resourceTypeLabel, utilizationUint32, limit.LimitBytes, limit.UsageBytes)
				recommendations := []string{
					"Check for resource leaks",
					"Review resource limits",
					"Consider scaling up pod resources",
				}
				if utilizationUint32 >= 95 {
					recommendations = append(recommendations, "Immediate action required - resource exhaustion imminent")
				}
				podName, namespace := rm.alertSubject()
				alert := &alerting.Alert{
					Severity:  severity,
					Title:     title,
					Message:   message,
					Timestamp: time.Now(),
					Source:    alerting.AlertSourceResourceMonitor,
					PodName:   podName,
					Namespace: namespace,
					Context: map[string]interface{}{
						"resource_type":       resourceTypeLabel,
						"utilization_percent": float64(utilizationUint32),
						"usage_bytes":         limit.UsageBytes,
						"limit_bytes":         limit.LimitBytes,
						"cgroup_path":         rm.cgroupPath,
					},
					Recommendations: recommendations,
				}
				manager.SendAlert(alert)
			}
			if rm.eventChan != nil {
				event := &events.Event{
					Type:        events.EventResourceLimit,
					PID:         0,
					CgroupID:    rm.cgroupInode,
					ProcessName: "cgroup",
					LatencyNS:   limit.LimitBytes,
					Error:       safeconv.Uint64ToInt32(utilization),
					Bytes:       limit.UsageBytes,
					TCPState:    resourceType,
					Target:      rm.cgroupPath,
					Timestamp:   uint64(time.Now().UnixNano()),
				}
				select {
				case rm.eventChan <- event:
					logger.Debug("Resource limit event sent",
						zap.String("resource_type", resourceTypeLabel),
						zap.Uint32("utilization", utilizationUint32),
						zap.Uint32("alert_level", alertLevel))
				default:
					logger.Warn("Failed to send resource limit event, channel full",
						zap.String("resource_type", resourceTypeLabel),
						zap.Uint32("utilization", utilizationUint32))
				}
			}
		}
	}
}

func (rm *ResourceMonitor) GetLimits() map[uint32]*ResourceLimit {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make(map[uint32]*ResourceLimit)
	for k, v := range rm.limits {
		result[k] = &ResourceLimit{
			LimitBytes:   v.LimitBytes,
			UsageBytes:   v.UsageBytes,
			LastUpdateNS: v.LastUpdateNS,
			ResourceType: v.ResourceType,
		}
	}
	return result
}

func getCgroupInode(cgroupPath string) (uint64, error) {
	info, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to get stat")
	}
	return uint64(stat.Ino), nil
}

// isCgroupV2 reports whether the cgroup hierarchy backing cgroupPath is the
// unified v2 hierarchy. A cgroup.controllers file exists only under v2 — never
// inside a v1 controller hierarchy — so its presence at the mount root
// (config.CgroupBasePath) is the authoritative signal, matching the check the
// tracer and CLI use. The per-path check is a fallback for callers whose base
// is itself a unified-hierarchy node. When neither is present the node is v1.
//
// The previous implementation probed for cpu/ and memory/ SUBDIRECTORIES of
// the pod path and returned an error otherwise. That never matched a real v1
// node — there the controllers are separate sibling hierarchies ABOVE the pod
// path (/sys/fs/cgroup/cpu,cpuacct/..., /sys/fs/cgroup/memory/...), not
// subdirectories of it — so v1 always fell through to "cannot determine
// version" and resource monitoring silently did nothing.
func isCgroupV2(cgroupPath string) bool {
	if _, err := os.Stat(filepath.Join(config.CgroupBasePath, "cgroup.controllers")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(cgroupPath, "cgroup.controllers")); err == nil {
		return true
	}
	return false
}

func readCgroupFile(path string) (string, error) {
	rel, ok := sysfs.CgroupRelative(path)
	if !ok {
		return "", fmt.Errorf("cgroup path %q is not under %s", path, config.CgroupBasePath)
	}
	file, err := sysfs.CgroupOpen(rel)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close cgroup file", zap.String("path", path), zap.Error(err))
		}
	}()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func parseCPUMax(cpuMax string) (quota, period uint64, unlimited bool) {
	cpuMax = strings.TrimSpace(cpuMax)
	if cpuMax == "max" {
		return 0, 0, true
	}
	parts := strings.Fields(cpuMax)
	if len(parts) >= 1 {
		quota, _ = strconv.ParseUint(parts[0], 10, 64)
	}
	if len(parts) >= 2 {
		period, _ = strconv.ParseUint(parts[1], 10, 64)
	} else {
		period = 100000
	}
	return quota, period, false
}

func parseMemoryMax(memMax string) uint64 {
	memMax = strings.TrimSpace(memMax)
	if memMax == "max" {
		return ^uint64(0)
	}
	val, _ := strconv.ParseUint(memMax, 10, 64)
	return val
}

// parseIOMax returns the largest single-channel bandwidth limit in io.max,
// the value exported as the IO limit metric.
func parseIOMax(ioMax string) uint64 {
	var maxBytes uint64
	for _, bps := range parseIOMaxChannels(ioMax) {
		maxBytes = max(maxBytes, bps)
	}
	return maxBytes
}

// parseIOMaxChannels parses io.max ("MAJ:MIN rbps=N wbps=N riops=max ...")
// into per-device, per-direction byte limits. "max" means unlimited and is
// left out.
func parseIOMaxChannels(ioMax string) map[ioChannel]uint64 {
	return parseIODeviceFields(ioMax, "rbps", "wbps")
}

// parseIOStatChannels parses io.stat ("MAJ:MIN rbytes=N wbytes=N ...") into
// cumulative per-device, per-direction byte counters.
func parseIOStatChannels(ioStat string) map[ioChannel]uint64 {
	return parseIODeviceFields(ioStat, "rbytes", "wbytes")
}

// parseIODeviceFields reads the readKey/writeKey values of every device in
// a cgroup v2 io file. A field without "=" names the device the following
// key=value fields belong to.
func parseIODeviceFields(data, readKey, writeKey string) map[ioChannel]uint64 {
	out := make(map[ioChannel]uint64)
	device := ""
	for _, field := range strings.Fields(data) {
		key, value, isPair := strings.Cut(field, "=")
		if !isPair {
			device = field
			continue
		}
		if key != readKey && key != writeKey {
			continue
		}
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			continue
		}
		out[ioChannel{device: device, write: key == writeKey}] = n
	}
	return out
}

// parseBlkioThrottleBps returns the largest per-device limit in
// blkio.throttle.{read,write}_bps_device.
func parseBlkioThrottleBps(ioData string) uint64 {
	var maxBps uint64
	for _, bps := range parseBlkioThrottleDevices(ioData) {
		maxBps = max(maxBps, bps)
	}
	return maxBps
}

// parseBlkioThrottleDevices parses blkio.throttle.{read,write}_bps_device,
// whose real format is two fields per line ("MAJ:MIN bytes_per_sec").
func parseBlkioThrottleDevices(ioData string) map[string]uint64 {
	out := make(map[string]uint64)
	scanner := bufio.NewScanner(strings.NewReader(ioData))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 2 && strings.Contains(parts[0], ":") {
			if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil && val > 0 {
				out[parts[0]] = val
			}
		}
	}
	return out
}

// parseBlkioServiceBytes sums the Read and Write rows of
// blkio.io_service_bytes.
func parseBlkioServiceBytes(ioData string) uint64 {
	var total uint64
	for _, b := range parseBlkioServiceChannels(ioData) {
		total += b
	}
	return total
}

// parseBlkioServiceChannels parses the Read and Write rows of
// blkio.io_service_bytes ("MAJ:MIN Read N") per device and direction,
// skipping the Sync/Async/Total aggregate rows.
func parseBlkioServiceChannels(ioData string) map[ioChannel]uint64 {
	out := make(map[ioChannel]uint64)
	scanner := bufio.NewScanner(strings.NewReader(ioData))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 3 && (parts[1] == "Read" || parts[1] == "Write") {
			if val, err := strconv.ParseUint(parts[2], 10, 64); err == nil {
				out[ioChannel{device: parts[0], write: parts[1] == "Write"}] = val
			}
		}
	}
	return out
}

func parseCPUStat(cpuStat string) uint64 {
	scanner := bufio.NewScanner(strings.NewReader(cpuStat))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "usage_usec") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				return val
			}
		}
	}
	return 0
}

// parseIOStat sums every device's read and write bytes in io.stat.
func parseIOStat(ioStat string) uint64 {
	var totalBytes uint64
	for _, b := range parseIOStatChannels(ioStat) {
		totalBytes += b
	}
	return totalBytes
}
