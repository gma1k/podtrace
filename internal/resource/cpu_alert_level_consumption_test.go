package resource

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAKernelCPULevelIsConsumedSoAnIdleCgroupStopsAlerting(t *testing.T) {
	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000
	rm.EnableBPFCPUSampler(quotaMap, alertsMap)
	if !rm.cpuQuotaInBPF {
		t.Fatal("a v2 cgroup's quota must reach the sampler")
	}

	key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}
	if err := alertsMap.Put(key, uint32(AlertCritical)); err != nil {
		t.Fatal(err)
	}

	rm.checkBPFCPUAlerts()
	if _, ok := alertsMap.get(key); ok {
		t.Fatal("the kernel level must be consumed when it is raised, or an idle cgroup keeps raising it")
	}
}

func TestACgroupV1MonitorKeepsTheUserSpaceCPUCheck(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	cgroupPath := writeCgroupV1Layout(t, base, "kubepods/pod1", map[string]map[string]string{
		"cpu,cpuacct": {"cpu.cfs_quota_us": "50000", "cpu.cfs_period_us": "100000"},
	})
	if _, err := os.Stat(filepath.Join(base, "cgroup.controllers")); err == nil {
		t.Fatal("fixture must be cgroup v1")
	}
	rm, err := NewResourceMonitor(cgroupPath, nil, nil, nil, "test-ns")
	if err != nil {
		t.Fatal(err)
	}
	quotaMap := newFakeInodeMap()
	rm.EnableBPFCPUSampler(quotaMap, newFakeBPFMap())

	if rm.cpuQuotaInBPF {
		t.Fatal("a v1 cgroup can never match the sampler's cgroup v2 id, so the kernel must not own its CPU check")
	}
	if _, ok := quotaMap.get(rm.cgroupInode); ok {
		t.Fatal("quota published for a cgroup the sampler cannot see")
	}
}

func TestAnIdleCgroupStillReportsItsCPUWhileTheKernelOwnsAlerting(t *testing.T) {
	eventChan := make(chan *events.Event, 4)
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, eventChan)
	rm.cpuQuotaMicros = 10000
	rm.cpuPeriodMicros = 100000
	rm.EnableBPFCPUSampler(newFakeInodeMap(), alertsMap)
	key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}
	if err := alertsMap.Put(key, uint32(AlertEmergency)); err != nil {
		t.Fatal(err)
	}

	now := uint64(time.Now().UnixNano())
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceCPU: {LimitBytes: 10000, UsageBytes: 5_000_000, LastUpdateNS: now, ResourceType: ResourceCPU},
	}
	rm.previousSamples[ResourceCPU] = resourceSample{usage: 5_000_000, wallNS: now - uint64(5*time.Second)}
	rm.mu.Unlock()

	rm.checkAlerts()

	select {
	case ev := <-eventChan:
		if ev.TCPState != ResourceCPU || ev.Error != 0 {
			t.Fatalf("event = %+v, want CPU at 0%% for an idle cgroup", ev)
		}
	default:
		t.Fatal("no CPU reading while the kernel owns alerting; the saturation gauge would keep the last spike")
	}
	if _, ok := alertsMap.get(key); !ok {
		t.Fatal("the user-space check touched the alert level the kernel owns")
	}
}
