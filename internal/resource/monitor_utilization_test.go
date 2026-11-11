package resource

import (
	"testing"
	"time"
)

func TestUtilizationPercent_CPURateNotCumulative(t *testing.T) {
	rm := &ResourceMonitor{
		cpuQuotaMicros:  100000, // 1 full CPU:
		cpuPeriodMicros: 100000, // 100ms per 100ms
		previousSamples: map[uint32]resourceSample{},
	}
	now := uint64(time.Now().UnixNano())

	const hourMicros = 3_600_000_000
	rm.previousSamples[ResourceCPU] = resourceSample{usage: hourMicros, wallNS: now - 5*uint64(time.Second)}
	limit := &ResourceLimit{
		LimitBytes:   rm.cpuQuotaMicros,
		UsageBytes:   hourMicros + 100_000, // +100ms CPU in 5s wall
		LastUpdateNS: now,
		ResourceType: ResourceCPU,
	}

	utilization, ok := rm.utilizationPercent(ResourceCPU, limit)
	if !ok {
		t.Fatal("expected a utilization value with two samples available")
	}
	if utilization > 5 {
		t.Errorf("utilization = %d%%, want ~2%% (cumulative counter must not saturate the rate)", utilization)
	}

	limit.UsageBytes = hourMicros + 5_000_000 // 5s CPU in 5s wall at 1-CPU quota
	utilization, ok = rm.utilizationPercent(ResourceCPU, limit)
	if !ok || utilization < 95 {
		t.Errorf("utilization = %d%% (ok=%v), want ~100%% for a saturated quota", utilization, ok)
	}
}

func TestUtilizationPercent_FirstSampleReportsNoData(t *testing.T) {
	rm := &ResourceMonitor{
		cpuQuotaMicros:  100000,
		cpuPeriodMicros: 100000,
		previousSamples: map[uint32]resourceSample{},
	}
	limit := &ResourceLimit{
		LimitBytes:   100000,
		UsageBytes:   999_999_999,
		LastUpdateNS: uint64(time.Now().UnixNano()),
		ResourceType: ResourceCPU,
	}
	if _, ok := rm.utilizationPercent(ResourceCPU, limit); ok {
		t.Error("first sample must report no data, not a (saturated) utilization")
	}
}

func TestUtilizationPercent_IORate(t *testing.T) {
	rm := &ResourceMonitor{
		previousSamples: map[uint32]resourceSample{},
		limits:          map[uint32]*ResourceLimit{ResourceIO: {LimitBytes: 1_000_000, ResourceType: ResourceIO}},
		ioLimits:        map[ioChannel]uint64{{device: "8:0", write: true}: 1_000_000},
	}
	now := uint64(time.Now().UnixNano())
	rm.recordIOSample(map[ioChannel]uint64{{device: "8:0", write: true}: 10_000_000_000}, now-uint64(time.Second))
	rm.recordIOSample(map[ioChannel]uint64{{device: "8:0", write: true}: 10_000_500_000}, now)

	utilization, ok := rm.utilizationPercent(ResourceIO, rm.limits[ResourceIO])
	if !ok || utilization < 45 || utilization > 55 {
		t.Errorf("utilization = %d%% (ok=%v), want ~50%% for 0.5 MB/s against a 1 MB/s limit", utilization, ok)
	}
}

func TestUtilizationPercent_MemoryStaysDirect(t *testing.T) {
	rm := &ResourceMonitor{previousSamples: map[uint32]resourceSample{}}
	limit := &ResourceLimit{LimitBytes: 1000, UsageBytes: 960, ResourceType: ResourceMemory}
	utilization, ok := rm.utilizationPercent(ResourceMemory, limit)
	if !ok || utilization != 96 {
		t.Errorf("utilization = %d%% (ok=%v), want 96%%", utilization, ok)
	}
}
