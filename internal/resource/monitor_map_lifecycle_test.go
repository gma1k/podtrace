package resource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCgroupV2Files(t *testing.T, files map[string]string) string {
	t.Helper()
	base := t.TempDir()
	useCgroupBase(t, base)
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu memory io"), 0o644); err != nil {
		t.Fatalf("write cgroup.controllers: %v", err)
	}
	cgroupPath := filepath.Join(base, "pod")
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rewriteCgroupFiles(t, cgroupPath, files)
	return cgroupPath
}

func rewriteCgroupFiles(t *testing.T, cgroupPath string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(cgroupPath, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func newV2MonitorWithMaps(t *testing.T, files map[string]string, limitsMap, alertsMap *fakeBPFMap) *ResourceMonitor {
	t.Helper()
	cgroupPath := writeCgroupV2Files(t, files)
	rm, err := NewResourceMonitor(cgroupPath, nil, nil, nil, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}
	rm.limitsMap = limitsMap
	rm.alertsMap = alertsMap
	if err := rm.readLimits(); err != nil {
		t.Fatalf("readLimits() error = %v", err)
	}
	return rm
}

func TestStop_ReleasesEveryBPFEntryOfTheCgroup(t *testing.T) {
	limitsMap := newFakeBPFMap()
	alertsMap := newFakeBPFMap()
	quotaMap := newFakeInodeMap()
	rm := newV2MonitorWithMaps(t, map[string]string{
		"cpu.max":    "50000 100000",
		"memory.max": "1048576",
		"io.max":     "8:0 rbps=1000 wbps=max",
	}, limitsMap, alertsMap)
	rm.EnableBPFCPUSampler(quotaMap, alertsMap)

	otherKey := resourceMapKey{CgroupID: rm.cgroupInode + 1, ResourceType: ResourceMemory}
	if err := limitsMap.Put(otherKey, limitMapValue{}); err != nil {
		t.Fatal(err)
	}
	if err := alertsMap.Put(otherKey, uint32(AlertWarning)); err != nil {
		t.Fatal(err)
	}
	if err := quotaMap.Put(rm.cgroupInode+1, cpuQuotaValue{QuotaMicros: 1, PeriodMicros: 1}); err != nil {
		t.Fatal(err)
	}
	for _, rt := range knownResourceTypes {
		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: rt}
		if _, ok := limitsMap.get(key); !ok {
			t.Fatalf("limit for type %d not published before Stop", rt)
		}
		if err := alertsMap.Put(key, uint32(AlertCritical)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := quotaMap.get(rm.cgroupInode); !ok {
		t.Fatal("CPU quota not published before Stop")
	}

	rm.Start(context.Background())
	rm.Stop()

	for _, rt := range knownResourceTypes {
		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: rt}
		if _, ok := limitsMap.get(key); ok {
			t.Errorf("cgroup_limits still holds type %d after Stop", rt)
		}
		if _, ok := alertsMap.get(key); ok {
			t.Errorf("cgroup_alerts still holds type %d after Stop", rt)
		}
	}
	if _, ok := quotaMap.get(rm.cgroupInode); ok {
		t.Error("cgroup_cpu_quota still holds the cgroup after Stop")
	}
	if _, ok := limitsMap.get(otherKey); !ok {
		t.Error("Stop removed another cgroup's limit")
	}
	if _, ok := alertsMap.get(otherKey); !ok {
		t.Error("Stop removed another cgroup's alert")
	}
	if _, ok := quotaMap.get(rm.cgroupInode + 1); !ok {
		t.Error("Stop removed another cgroup's CPU quota")
	}
}

func TestStop_ToleratesFailingMapDeletes(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.limitsMap = failingBPFMap{}
	rm.alertsMap = failingBPFMap{}
	rm.cpuQuotaMap = failingBPFMap{}
	rm.cpuQuotaInBPF = true
	rm.publishedTypes[ResourceMemory] = struct{}{}

	rm.Start(context.Background())
	rm.Stop()

	if rm.cpuQuotaInBPF || len(rm.publishedTypes) != 0 {
		t.Errorf("state after Stop: cpuQuotaInBPF=%v published=%v", rm.cpuQuotaInBPF, rm.publishedTypes)
	}
}

func TestRefreshLimits_UnpublishesARemovedLimit(t *testing.T) {
	limitsMap := newFakeBPFMap()
	alertsMap := newFakeBPFMap()
	rm := newV2MonitorWithMaps(t, map[string]string{"memory.max": "1048576"}, limitsMap, alertsMap)
	key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceMemory}
	if err := alertsMap.Put(key, uint32(AlertCritical)); err != nil {
		t.Fatal(err)
	}

	rewriteCgroupFiles(t, rm.cgroupPath, map[string]string{"memory.max": "max"})
	rm.refreshLimits()
	if err := rm.updateResourceUsage(); err != nil {
		t.Fatal(err)
	}

	if _, ok := rm.GetLimits()[ResourceMemory]; ok {
		t.Error("memory limit kept after memory.max became max")
	}
	if _, ok := limitsMap.get(key); ok {
		t.Error("removed memory limit still in cgroup_limits")
	}
	if _, ok := alertsMap.get(key); ok {
		t.Error("removed memory limit still has an alert in cgroup_alerts")
	}
}

func TestSyncToBPF_TracksTypesWithoutALimitsMap(t *testing.T) {
	alertsMap := newFakeBPFMap()
	rm := &ResourceMonitor{
		alertsMap: alertsMap,
		limits:    map[uint32]*ResourceLimit{ResourceMemory: {LimitBytes: 10, ResourceType: ResourceMemory}},
	}
	if err := rm.syncToBPF(); err != nil {
		t.Fatal(err)
	}
	key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceMemory}
	if err := alertsMap.Put(key, uint32(AlertWarning)); err != nil {
		t.Fatal(err)
	}

	delete(rm.limits, ResourceMemory)
	if err := rm.syncToBPF(); err != nil {
		t.Fatal(err)
	}
	if _, ok := alertsMap.get(key); ok {
		t.Error("alert of a removed limit survived without a limits map")
	}
}

func TestRefreshLimits_PicksUpInPlaceResize(t *testing.T) {
	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newV2MonitorWithMaps(t, map[string]string{
		"cpu.max":    "50000 100000",
		"memory.max": "1048576",
	}, newFakeBPFMap(), alertsMap)
	rm.EnableBPFCPUSampler(quotaMap, alertsMap)
	rm.mu.Lock()
	rm.limits[ResourceCPU].UsageBytes = 4242
	rm.limits[ResourceCPU].LastUpdateNS = 777
	rm.mu.Unlock()

	rewriteCgroupFiles(t, rm.cgroupPath, map[string]string{
		"cpu.max":    "200000 100000",
		"memory.max": "4194304",
	})
	rm.refreshLimits()

	limits := rm.GetLimits()
	if limits[ResourceCPU].LimitBytes != 200000 || limits[ResourceMemory].LimitBytes != 4194304 {
		t.Errorf("limits after resize: cpu=%d memory=%d", limits[ResourceCPU].LimitBytes, limits[ResourceMemory].LimitBytes)
	}
	if limits[ResourceCPU].UsageBytes != 4242 || limits[ResourceCPU].LastUpdateNS != 777 {
		t.Error("resize discarded the sampled CPU usage the next rate needs")
	}
	got, ok := quotaMap.get(rm.cgroupInode)
	if !ok || got.(cpuQuotaValue).QuotaMicros != 200000 {
		t.Errorf("BPF quota after resize = %v (ok=%v), want 200000", got, ok)
	}

	rewriteCgroupFiles(t, rm.cgroupPath, map[string]string{"cpu.max": "max 100000"})
	rm.refreshLimits()
	if _, ok := quotaMap.get(rm.cgroupInode); ok {
		t.Error("BPF quota kept after the CPU limit was removed")
	}
	if _, ok := rm.GetLimits()[ResourceCPU]; ok {
		t.Error("CPU limit kept after cpu.max became max")
	}
}

func TestRefreshLimits_UnchangedQuotaDoesNotRewriteTheSampler(t *testing.T) {
	rm := newV2MonitorWithMaps(t, map[string]string{"cpu.max": "50000 100000"}, newFakeBPFMap(), newFakeBPFMap())
	quotaMap := newFakeInodeMap()
	rm.EnableBPFCPUSampler(quotaMap, newFakeBPFMap())
	if err := quotaMap.Delete(rm.cgroupInode); err != nil {
		t.Fatal(err)
	}

	rm.refreshLimits()

	if _, ok := quotaMap.get(rm.cgroupInode); ok {
		t.Error("an unchanged quota was rewritten on every refresh")
	}
}

func TestRefreshLimits_FailedQuotaSyncIsLogged(t *testing.T) {
	rm := newV2MonitorWithMaps(t, map[string]string{"cpu.max": "50000 100000"}, newFakeBPFMap(), newFakeBPFMap())
	rm.cpuQuotaMap = failingBPFMap{}

	rewriteCgroupFiles(t, rm.cgroupPath, map[string]string{"cpu.max": "60000 100000"})
	rm.refreshLimits()

	if rm.cpuQuotaInBPF {
		t.Error("cpuQuotaInBPF set although the quota write failed")
	}
}

func TestCheckAlerts_CPUFallsBackToUserSpaceWhenQuotaMapIsFull(t *testing.T) {
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, nil)
	rm.cpuQuotaMicros = 100000
	rm.cpuPeriodMicros = 100000

	rm.EnableBPFCPUSampler(failingBPFMap{}, alertsMap)
	if !rm.cpuSamplerOn || rm.cpuQuotaInBPF {
		t.Fatalf("sampler=%v quotaInBPF=%v, want sampler on without the quota in BPF", rm.cpuSamplerOn, rm.cpuQuotaInBPF)
	}

	now := uint64(time.Now().UnixNano())
	rm.mu.Lock()
	rm.previousSamples[ResourceCPU] = resourceSample{usage: 0, wallNS: now - uint64(time.Second)}
	rm.limits[ResourceCPU] = &ResourceLimit{LimitBytes: 100000, UsageBytes: 1_000_000, LastUpdateNS: now, ResourceType: ResourceCPU}
	rm.mu.Unlock()

	rm.checkAlerts()
	rm.checkBPFCPUAlerts()

	if level, ok := alertsMap.get(resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}); !ok || level != uint32(AlertEmergency) {
		t.Errorf("CPU alert = %v (ok=%v), want the user-space check to raise emergency", level, ok)
	}
}

func TestCheckAlerts_CPUStaysWithTheKernelWhenQuotaIsInBPF(t *testing.T) {
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, nil)
	rm.cpuQuotaMicros = 100000
	rm.cpuPeriodMicros = 100000
	rm.EnableBPFCPUSampler(newFakeInodeMap(), alertsMap)

	now := uint64(time.Now().UnixNano())
	rm.mu.Lock()
	rm.previousSamples[ResourceCPU] = resourceSample{usage: 0, wallNS: now - uint64(time.Second)}
	rm.limits[ResourceCPU] = &ResourceLimit{LimitBytes: 100000, UsageBytes: 1_000_000, LastUpdateNS: now, ResourceType: ResourceCPU}
	rm.mu.Unlock()

	rm.checkAlerts()

	if _, ok := alertsMap.get(resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}); ok {
		t.Error("user-space check wrote a CPU alert while the kernel sampler owns CPU")
	}
}
