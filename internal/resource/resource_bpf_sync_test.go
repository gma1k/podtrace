package resource

import (
	"errors"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/events"
)

type failingBPFMap struct{}

var errFakeMap = errors.New("fake bpf map failure")

func (failingBPFMap) Put(_, _ interface{}) error    { return errFakeMap }
func (failingBPFMap) Delete(_ interface{}) error    { return errFakeMap }
func (failingBPFMap) Lookup(_, _ interface{}) error { return errFakeMap }

func TestReadV1ControllerFile_NoControllers(t *testing.T) {
	_, err := readV1ControllerFile(nil, "kubepods/pod1", "cpu.cfs_quota_us")
	if err == nil {
		t.Fatal("expected an error when no controllers are supplied")
	}
	if !strings.Contains(err.Error(), "no controller mount found") {
		t.Errorf("error = %v, want it to mention no controller mount found", err)
	}
}

func TestEnableBPFCPUSampler_NilMapsNoop(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.EnableBPFCPUSampler(nil, nil)
	if rm.cpuSamplerOn {
		t.Error("sampler must stay off when maps are nil")
	}
}

func TestEnableBPFCPUSampler_SyncErrorWarns(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000

	rm.EnableBPFCPUSampler(failingBPFMap{}, newFakeBPFMap())

	if !rm.cpuSamplerOn {
		t.Error("sampler should be marked on even when the initial sync fails")
	}
}

func TestSyncCPUQuota_NilMap(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	if err := rm.syncCPUQuota(); err != nil {
		t.Errorf("syncCPUQuota() with nil map = %v, want nil", err)
	}
}

func TestSyncCPUQuota_DeleteError(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMap = failingBPFMap{}
	rm.cpuQuotaMicros = 0
	rm.cpuPeriodMicros = 0

	err := rm.syncCPUQuota()
	if err == nil {
		t.Fatal("expected an error when clearing the quota entry fails")
	}
	if !strings.Contains(err.Error(), "clear CPU quota") {
		t.Errorf("error = %v, want it to mention clear CPU quota", err)
	}
}

func TestSyncCPUQuota_PutError(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMap = failingBPFMap{}
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000

	err := rm.syncCPUQuota()
	if err == nil {
		t.Fatal("expected an error when writing the quota entry fails")
	}
	if !strings.Contains(err.Error(), "put CPU quota") {
		t.Errorf("error = %v, want it to mention put CPU quota", err)
	}
}

func TestCheckBPFCPUAlerts_LookupError(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuAlertsReadMap = failingBPFMap{}
	rm.cpuSamplerOn = true
	rm.checkBPFCPUAlerts()
}

func TestCheckBPFCPUAlerts_LevelNone(t *testing.T) {
	ch := useEnabledAlertManager(t)
	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000
	rm.EnableBPFCPUSampler(quotaMap, alertsMap)

	key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}
	if err := alertsMap.Put(key, uint32(AlertNone)); err != nil {
		t.Fatalf("seed alert level: %v", err)
	}

	rm.checkBPFCPUAlerts()

	select {
	case a := <-ch:
		if a.Source == "resource_monitor_bpf" {
			t.Fatalf("no alert expected for AlertNone, got %+v", a)
		}
	default:
	}
}

func TestCheckBPFCPUAlerts_NoManager(t *testing.T) {
	orig := alerting.GetGlobalManager()
	t.Cleanup(func() { alerting.SetGlobalManager(orig) })
	alerting.SetGlobalManager(nil)

	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000
	rm.EnableBPFCPUSampler(quotaMap, alertsMap)

	key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}
	if err := alertsMap.Put(key, uint32(AlertCritical)); err != nil {
		t.Fatalf("seed alert level: %v", err)
	}

	rm.checkBPFCPUAlerts()
}

func TestUtilizationPercent_NoDataEdgeCases(t *testing.T) {
	rm := &ResourceMonitor{previousSamples: map[uint32]resourceSample{}}

	cpuLimit := &ResourceLimit{LimitBytes: 100000, UsageBytes: 5000, LastUpdateNS: 100, ResourceType: ResourceCPU}
	if _, ok := rm.utilizationPercent(ResourceCPU, cpuLimit); ok {
		t.Error("CPU with zero quota/period must report no data")
	}

	ioLimit := &ResourceLimit{LimitBytes: 1_000_000, UsageBytes: 500, LastUpdateNS: 100, ResourceType: ResourceIO}
	if _, ok := rm.utilizationPercent(ResourceIO, ioLimit); ok {
		t.Error("IO without a prior sample must report no data")
	}
}

func TestCheckAlerts_CPUSamplerOnAndNoData(t *testing.T) {
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, make(chan *events.Event, 4))
	rm.cpuSamplerOn = true

	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceCPU: {LimitBytes: 100000, UsageBytes: 5000, ResourceType: ResourceCPU},
		ResourceIO:  {LimitBytes: 1_000_000, UsageBytes: 500, LastUpdateNS: 100, ResourceType: ResourceIO},
	}
	rm.mu.Unlock()

	rm.checkAlerts()

	for _, rt := range []uint32{ResourceCPU, ResourceIO} {
		if _, ok := alertsMap.get(resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: rt}); ok {
			t.Errorf("expected no alert entry for resource type %d", rt)
		}
	}
}

func TestSyncToBPF_PutErrorLogged(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.limitsMap = failingBPFMap{}
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceCPU: {LimitBytes: 100, ResourceType: ResourceCPU},
	}
	rm.mu.Unlock()

	if err := rm.syncToBPF(); err != nil {
		t.Errorf("syncToBPF logs put failures but returns nil, got %v", err)
	}
}

func TestCheckAlerts_MapPutErrorWarns(t *testing.T) {
	useEnabledAlertManager(t)
	rm := newMonitorWithFakeMaps(t, nil, nil, make(chan *events.Event, 4))
	rm.alertsMap = failingBPFMap{}
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 96, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	rm.checkAlerts()
}

func TestCheckAlerts_MapDeleteErrorWarns(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, make(chan *events.Event, 4))
	rm.alertsMap = failingBPFMap{}
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 10, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	rm.checkAlerts()
}

func TestReadLimitsV1_BlkioWriteExceedsRead(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	cgroupPath := writeCgroupV1Layout(t, base, "kubepods/pod-w", map[string]map[string]string{
		"blkio": {
			"blkio.throttle.read_bps_device":  "8:0 1048576",
			"blkio.throttle.write_bps_device": "8:0 4194304",
		},
	})

	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, make(chan *events.Event, 4), "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	io := monitor.GetLimits()[ResourceIO]
	if io == nil {
		t.Fatal("expected an IO limit derived from the blkio throttles")
	}
	if io.LimitBytes != 4194304 {
		t.Errorf("IO limit = %d, want 4194304 (the larger write throttle)", io.LimitBytes)
	}
}

func TestUpdateResourceUsage_SnapshotsPreviousSamples(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceCPU: {LimitBytes: 100000, UsageBytes: 4200, LastUpdateNS: 12345, ResourceType: ResourceCPU},
	}
	rm.mu.Unlock()

	if err := rm.updateResourceUsage(); err != nil {
		t.Fatalf("updateResourceUsage() error = %v", err)
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()
	prev, ok := rm.previousSamples[ResourceCPU]
	if !ok || prev.usage != 4200 || prev.wallNS != 12345 {
		t.Errorf("previous sample = %+v (ok=%v), want usage 4200 wallNS 12345", prev, ok)
	}
}
