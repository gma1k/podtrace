package resource

import (
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

// TestParseBlkioThrottleBps_RealKernelFormat: the v1 throttle files are
// two fields per line ("MAJ:MIN bytes_per_sec"); the old parser required
// three fields, so a configured v1 IO limit never parsed (the fixtures
// used a fictional format).
func TestParseBlkioThrottleBps_RealKernelFormat(t *testing.T) {
	if got := parseBlkioThrottleBps("8:0 2097152"); got != 2097152 {
		t.Errorf("single device = %d, want 2097152", got)
	}
	if got := parseBlkioThrottleBps("8:0 2097152\n8:16 4194304"); got != 4194304 {
		t.Errorf("multi device = %d, want the strictest (largest) limit 4194304", got)
	}
	if got := parseBlkioThrottleBps(""); got != 0 {
		t.Errorf("empty = %d, want 0", got)
	}
	if got := parseBlkioThrottleBps("garbage line"); got != 0 {
		t.Errorf("garbage = %d, want 0", got)
	}
}

// TestParseBlkioServiceBytes_SkipsAggregateRows: io_service_bytes carries
// Read/Write/Sync/Async/Total rows per device; summing every row counted
// each byte roughly three times.
func TestParseBlkioServiceBytes_SkipsAggregateRows(t *testing.T) {
	data := "8:0 Read 100\n8:0 Write 200\n8:0 Sync 250\n8:0 Async 50\n8:0 Total 300\nTotal 300"
	if got := parseBlkioServiceBytes(data); got != 300 {
		t.Errorf("usage = %d, want 300 (Read+Write only, no aggregate rows)", got)
	}
}

// TestParseIOMax_MultiDevice: io.max has one line per device; reading only
// the first line of the file dropped every other device's limit.
func TestParseIOMax_MultiDevice(t *testing.T) {
	data := "8:0 rbps=1000 wbps=2000\n8:16 rbps=9000 wbps=500"
	if got := parseIOMax(data); got != 9000 {
		t.Errorf("limit = %d, want 9000 from the SECOND device line", got)
	}
}

// TestCheckAlerts_HonorsConfiguredThresholds: the Go-side alert evaluation
// hardcoded 95/90/80 while the BPF side honored PODTRACE_ALERT_*_PCT —
// the two halves disagreed whenever the operator tuned the thresholds.
func TestCheckAlerts_HonorsConfiguredThresholds(t *testing.T) {
	saveWarn, saveCrit, saveEmerg := config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct
	config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct = 50, 60, 70
	t.Cleanup(func() {
		config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct = saveWarn, saveCrit, saveEmerg
	})

	alertsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, nil)

	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 65, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	rm.checkAlerts()

	raw, ok := alertsMap.get(resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: ResourceMemory})
	if !ok {
		t.Fatal("expected an alert entry: 65% breaches the configured 60% critical threshold")
	}
	if level := raw.(uint32); level != AlertCritical {
		t.Errorf("level = %d, want %d (65%% with crit=60 emerg=70)", level, AlertCritical)
	}
}
