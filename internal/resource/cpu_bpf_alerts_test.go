package resource

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// fakeInodeMap is the cgroup_cpu_quota fake: keyed by the raw cgroup inode
// (u64), matching how syncCPUQuota writes it. Satisfies bpfLimitMap.
type fakeInodeMap struct {
	mu      sync.Mutex
	entries map[uint64]interface{}
}

func newFakeInodeMap() *fakeInodeMap {
	return &fakeInodeMap{entries: make(map[uint64]interface{})}
}

func (f *fakeInodeMap) Put(key, value interface{}) error {
	k, ok := key.(uint64)
	if !ok {
		return fmt.Errorf("fakeInodeMap.Put: key must be uint64, got %T", key)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[k] = value
	return nil
}

func (f *fakeInodeMap) Delete(key interface{}) error {
	k, ok := key.(uint64)
	if !ok {
		return fmt.Errorf("fakeInodeMap.Delete: key must be uint64, got %T", key)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.entries[k]; !exists {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeInodeMap) get(key uint64) (interface{}, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.entries[key]
	return v, ok
}

// TestEnableBPFCPUSampler_SyncsQuota verifies that enabling the sampler writes
// the cgroup's quota/period into the quota map keyed by the cgroup inode and
// marks the sampler on (so checkAlerts cedes CPU to the kernel).
func TestEnableBPFCPUSampler_SyncsQuota(t *testing.T) {
	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000

	rm.EnableBPFCPUSampler(quotaMap, alertsMap)

	if !rm.cpuSamplerOn {
		t.Fatal("sampler not marked on after EnableBPFCPUSampler")
	}
	got, ok := quotaMap.get(rm.cgroupInode)
	if !ok {
		t.Fatal("quota not written to map")
	}
	q, ok := got.(cpuQuotaValue)
	if !ok {
		t.Fatalf("quota value type = %T, want cpuQuotaValue", got)
	}
	if q.QuotaMicros != 50000 || q.PeriodMicros != 100000 {
		t.Errorf("quota = %+v, want {50000 100000}", q)
	}
}

// TestSyncCPUQuota_ClearsWhenUnknown removes any stale quota entry when the
// cgroup has no CPU limit, so the sampler stops computing a percentage.
func TestSyncCPUQuota_ClearsWhenUnknown(t *testing.T) {
	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	_ = quotaMap.Put(rm.cgroupInode, cpuQuotaValue{QuotaMicros: 1, PeriodMicros: 1})
	rm.cpuQuotaMicros = 0
	rm.cpuPeriodMicros = 0

	rm.EnableBPFCPUSampler(quotaMap, alertsMap)

	if _, ok := quotaMap.get(rm.cgroupInode); ok {
		t.Error("stale quota entry not cleared for cgroup without CPU limit")
	}
}

// TestCheckBPFCPUAlerts_FiresOnKernelLevel raises an alert when the sampler has
// written a non-zero CPU alert level, and stays silent when none is set.
func TestCheckBPFCPUAlerts_FiresOnKernelLevel(t *testing.T) {
	ch := useEnabledAlertManager(t)

	quotaMap := newFakeInodeMap()
	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.cpuQuotaMicros = 50000
	rm.cpuPeriodMicros = 100000
	rm.EnableBPFCPUSampler(quotaMap, alertsMap)

	// No kernel level yet: must stay silent.
	rm.checkBPFCPUAlerts()
	select {
	case a := <-ch:
		if a.Source == "resource_monitor_bpf" {
			t.Fatalf("alert fired with no kernel level set: %+v", a)
		}
	default:
	}

	// Kernel raised a critical CPU alert.
	key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceCPU}
	if err := alertsMap.Put(key, uint32(AlertCritical)); err != nil {
		t.Fatalf("seed alert level: %v", err)
	}

	rm.checkBPFCPUAlerts()

	deadline := time.After(time.Second)
	for {
		select {
		case a := <-ch:
			if a.Source != "resource_monitor_bpf" {
				continue
			}
			if a.Namespace != "test-ns" {
				t.Errorf("alert namespace = %q, want test-ns", a.Namespace)
			}
			if got := a.Context["resource_type"]; got != "cpu" {
				t.Errorf("alert resource_type = %v, want cpu", got)
			}
			return
		case <-deadline:
			t.Fatal("expected a CPU alert from the BPF sampler, got none")
		}
	}
}

// TestCheckBPFCPUAlerts_NoopWhenSamplerOff does nothing when the sampler was
// never enabled (the userspace path still owns CPU).
func TestCheckBPFCPUAlerts_NoopWhenSamplerOff(t *testing.T) {
	ch := useEnabledAlertManager(t)
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)

	rm.checkBPFCPUAlerts() // sampler off, no maps

	select {
	case a := <-ch:
		if a.Source == "resource_monitor_bpf" {
			t.Fatalf("alert fired while sampler off: %+v", a)
		}
	default:
	}
}
