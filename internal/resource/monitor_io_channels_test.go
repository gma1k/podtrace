package resource

import (
	"reflect"
	"testing"
	"time"
)

func TestParseIOMaxChannels_PerDeviceAndDirection(t *testing.T) {
	got := parseIOMaxChannels("8:0 rbps=1000 wbps=max riops=max wiops=max\n8:16 rbps=max wbps=2000 riops=50 wiops=max\n")
	want := map[ioChannel]uint64{
		{device: "8:0"}:               1000,
		{device: "8:16", write: true}: 2000,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseIOMaxChannels = %v, want %v", got, want)
	}
}

func TestParseIOStatChannels_PerDeviceAndDirection(t *testing.T) {
	got := parseIOStatChannels("8:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=99 dios=0\n8:16 rbytes=30 wbytes=40\n")
	want := map[ioChannel]uint64{
		{device: "8:0"}:               10,
		{device: "8:0", write: true}:  20,
		{device: "8:16"}:              30,
		{device: "8:16", write: true}: 40,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseIOStatChannels = %v, want %v", got, want)
	}
}

func TestParseBlkioChannels_PerDeviceAndDirection(t *testing.T) {
	throttles := parseBlkioThrottleDevices("8:0 1000\n8:16 0\nbogus\n")
	if !reflect.DeepEqual(throttles, map[string]uint64{"8:0": 1000}) {
		t.Errorf("parseBlkioThrottleDevices = %v", throttles)
	}
	service := parseBlkioServiceChannels("8:0 Read 5\n8:0 Write 7\n8:0 Total 12\n8:16 Read x\n")
	want := map[ioChannel]uint64{{device: "8:0"}: 5, {device: "8:0", write: true}: 7}
	if !reflect.DeepEqual(service, want) {
		t.Errorf("parseBlkioServiceChannels = %v, want %v", service, want)
	}
}

func TestIOChannelUtilization(t *testing.T) {
	read0 := ioChannel{device: "8:0"}
	write0 := ioChannel{device: "8:0", write: true}
	read16 := ioChannel{device: "8:16"}
	second := uint64(time.Second)

	tests := []struct {
		name     string
		limits   map[ioChannel]uint64
		previous map[ioChannel]uint64
		current  map[ioChannel]uint64
		want     float64
		wantOK   bool
	}{
		{
			name:     "traffic on unlimited device and direction is ignored",
			limits:   map[ioChannel]uint64{read0: 1000},
			previous: map[ioChannel]uint64{read0: 0, write0: 0, read16: 0},
			current:  map[ioChannel]uint64{read0: 100, write0: 1_000_000, read16: 1_000_000},
			want:     10,
			wantOK:   true,
		},
		{
			name:     "busiest limited channel wins",
			limits:   map[ioChannel]uint64{read0: 1000, write0: 100},
			previous: map[ioChannel]uint64{read0: 0, write0: 0},
			current:  map[ioChannel]uint64{read0: 500, write0: 90},
			want:     90,
			wantOK:   true,
		},
		{
			name:     "channel absent from io.stat moved nothing",
			limits:   map[ioChannel]uint64{read16: 1000},
			previous: map[ioChannel]uint64{},
			current:  map[ioChannel]uint64{read0: 5000},
			want:     0,
			wantOK:   true,
		},
		{
			name:     "counter reset is skipped",
			limits:   map[ioChannel]uint64{read0: 1000},
			previous: map[ioChannel]uint64{read0: 500},
			current:  map[ioChannel]uint64{read0: 10},
			wantOK:   false,
		},
		{
			name:     "zero limit is skipped",
			limits:   map[ioChannel]uint64{read0: 0},
			previous: map[ioChannel]uint64{},
			current:  map[ioChannel]uint64{read0: 10},
			wantOK:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ioChannelUtilization(tt.limits, tt.previous, tt.current, second)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Errorf("ioChannelUtilization = %v (ok=%v), want %v (ok=%v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestUpdateUsageV2_IOUtilizationUsesTheLimitedChannelOnly(t *testing.T) {
	rm := newV2MonitorWithMaps(t, map[string]string{
		"io.max":  "8:0 rbps=1000000 wbps=max",
		"io.stat": "8:0 rbytes=0 wbytes=0\n8:16 rbytes=0 wbytes=0",
	}, newFakeBPFMap(), newFakeBPFMap())

	if err := rm.updateResourceUsage(); err != nil {
		t.Fatal(err)
	}
	if _, ok := rm.utilizationPercent(ResourceIO, rm.GetLimits()[ResourceIO]); ok {
		t.Fatal("first IO sample must report no data")
	}

	rewriteCgroupFiles(t, rm.cgroupPath, map[string]string{
		"io.stat": "8:0 rbytes=1000 wbytes=900000000\n8:16 rbytes=900000000 wbytes=900000000",
	})
	rm.mu.Lock()
	rm.ioPreviousNS -= uint64(time.Second)
	rm.mu.Unlock()
	if err := rm.updateResourceUsage(); err != nil {
		t.Fatal(err)
	}

	rm.mu.RLock()
	utilization, ok := rm.utilizationPercent(ResourceIO, rm.limits[ResourceIO])
	usage := rm.limits[ResourceIO].UsageBytes
	rm.mu.RUnlock()
	if !ok || utilization > 1 {
		t.Errorf("IO utilization = %d%% (ok=%v); unlimited write and other-device traffic must not count", utilization, ok)
	}
	if usage != 1000+3*900000000 {
		t.Errorf("IO usage metric = %d, want every device's bytes", usage)
	}
}

func TestRefreshLimits_RemovedIOLimitResetsTheRate(t *testing.T) {
	rm := newV2MonitorWithMaps(t, map[string]string{
		"io.max":  "8:0 rbps=1000",
		"io.stat": "8:0 rbytes=10",
	}, newFakeBPFMap(), newFakeBPFMap())
	if err := rm.updateResourceUsage(); err != nil {
		t.Fatal(err)
	}

	rewriteCgroupFiles(t, rm.cgroupPath, map[string]string{"io.max": "8:0 rbps=max"})
	rm.refreshLimits()

	if rm.ioPrevious != nil || rm.ioPreviousNS != 0 || rm.ioUtilizationOK || rm.ioLimits != nil {
		t.Error("IO rate state kept after the IO limit was removed")
	}
	if _, ok := rm.GetLimits()[ResourceIO]; ok {
		t.Error("IO limit kept after io.max became max")
	}
}

func TestReadLimitsV1_PerDirectionIOChannels(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	cgroupPath := writeCgroupV1Layout(t, base, "kubepods/pod-io", map[string]map[string]string{
		"blkio": {
			"blkio.throttle.read_bps_device":  "8:0 1048576",
			"blkio.throttle.write_bps_device": "8:16 4194304",
			"blkio.io_service_bytes":          "8:0 Read 10\n8:16 Write 20\n8:16 Read 99999999",
		},
	})
	rm, err := NewResourceMonitor(cgroupPath, nil, nil, nil, "test-ns")
	if err != nil {
		t.Fatal(err)
	}

	want := map[ioChannel]uint64{{device: "8:0"}: 1048576, {device: "8:16", write: true}: 4194304}
	if !reflect.DeepEqual(rm.ioLimits, want) {
		t.Errorf("v1 IO limits = %v, want %v", rm.ioLimits, want)
	}

	if err := rm.updateResourceUsage(); err != nil {
		t.Fatal(err)
	}
	if rm.ioPrevious[ioChannel{device: "8:16", write: true}] != 20 {
		t.Errorf("v1 IO sample = %v", rm.ioPrevious)
	}
}

func TestReadLimitsV1_UnlimitedMemoryIsNoLimit(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	cgroupPath := writeCgroupV1Layout(t, base, "kubepods/pod-unlimited", map[string]map[string]string{
		"memory": {"memory.limit_in_bytes": "9223372036854771712\n"},
	})
	rm, err := NewResourceMonitor(cgroupPath, nil, nil, nil, "test-ns")
	if err != nil {
		t.Fatal(err)
	}
	if limit, ok := rm.GetLimits()[ResourceMemory]; ok {
		t.Errorf("v1 unlimited memory exported as a %d-byte limit", limit.LimitBytes)
	}
}

func TestFiniteMemoryLimit(t *testing.T) {
	for input, want := range map[uint64]uint64{
		0:                            0,
		1 << 30:                      1 << 30,
		0x7FFFFFFFFFFFF000:           0,
		0x7FFFFFFFFFFF0000:           0,
		^uint64(0):                   0,
		unlimitedMemoryThreshold - 1: unlimitedMemoryThreshold - 1,
	} {
		if got := finiteMemoryLimit(input); got != want {
			t.Errorf("finiteMemoryLimit(%#x) = %#x, want %#x", input, got, want)
		}
	}
}

func TestRefreshLimits_ReadsV1Limits(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	cgroupPath := writeCgroupV1Layout(t, base, "kubepods/pod-v1", map[string]map[string]string{
		"memory": {"memory.limit_in_bytes": "1048576"},
	})
	rm, err := NewResourceMonitor(cgroupPath, nil, nil, nil, "test-ns")
	if err != nil {
		t.Fatal(err)
	}

	rewriteCgroupFiles(t, base+"/memory/kubepods/pod-v1", map[string]string{"memory.limit_in_bytes": "2097152"})
	rm.refreshLimits()

	if got := rm.GetLimits()[ResourceMemory]; got == nil || got.LimitBytes != 2097152 {
		t.Errorf("v1 memory limit after refresh = %+v, want 2097152", got)
	}
}

func TestReadLimitsV2_ZeroBandwidthIsNoLimit(t *testing.T) {
	rm := newV2MonitorWithMaps(t, map[string]string{"io.max": "8:0 rbps=0 wbps=1000"}, newFakeBPFMap(), newFakeBPFMap())

	want := map[ioChannel]uint64{{device: "8:0", write: true}: 1000}
	if !reflect.DeepEqual(rm.ioLimits, want) {
		t.Errorf("IO limits = %v, want only the write channel", rm.ioLimits)
	}
}
