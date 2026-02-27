package report

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

type mockDiagnostician struct {
	events             []*events.Event
	startTime          time.Time
	endTime            time.Time
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
}

func (m *mockDiagnostician) GetEvents() []*events.Event {
	return m.events
}

func (m *mockDiagnostician) FilterEvents(eventType events.EventType) []*events.Event {
	var filtered []*events.Event
	for _, e := range m.events {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (m *mockDiagnostician) CalculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}

func (m *mockDiagnostician) StartTime() time.Time {
	return m.startTime
}

func (m *mockDiagnostician) EndTime() time.Time {
	return m.endTime
}

func (m *mockDiagnostician) ErrorRateThreshold() float64 {
	return m.errorRateThreshold
}

func (m *mockDiagnostician) RTTSpikeThreshold() float64 {
	return m.rttSpikeThreshold
}

func (m *mockDiagnostician) FSSlowThreshold() float64 {
	return m.fsSlowThreshold
}

func TestGenerateSummarySection(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSummarySection(d, duration)
	if result == "" {
		t.Error("Expected summary section")
	}
}

func TestGenerateDNSSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateDNSSection(d, duration)
	if result != "" {
		t.Error("Expected empty DNS section for no events")
	}
}

func TestGenerateDNSSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateDNSSection(d, duration)
	if result == "" {
		t.Error("Expected DNS section")
	}
}

func TestGenerateTCPSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPSection(d, duration)
	if result != "" {
		t.Error("Expected empty TCP section for no events")
	}
}

func TestGenerateTCPSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTCPSend, LatencyNS: 1000000, Bytes: 1024},
			{Type: events.EventTCPRecv, LatencyNS: 2000000, Bytes: 2048},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		rttSpikeThreshold:  100.0,
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPSection(d, duration)
	if result == "" {
		t.Error("Expected TCP section")
	}
}

func TestGenerateConnectionSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateConnectionSection(d, duration)
	if result != "" {
		t.Error("Expected empty connection section for no events")
	}
}

func TestGenerateConnectionSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateConnectionSection(d, duration)
	if result == "" {
		t.Error("Expected connection section")
	}
}

func TestGenerateFileSystemSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateFileSystemSection(d, duration)
	if result != "" {
		t.Error("Expected empty filesystem section for no events")
	}
}

func TestGenerateFileSystemSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096},
			{Type: events.EventWrite, LatencyNS: 3000000, Target: "/tmp/file2", Bytes: 2048},
		},
		startTime:        time.Now(),
		endTime:          time.Now().Add(1 * time.Second),
		fsSlowThreshold: 10.0,
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateFileSystemSection(d, duration)
	if result == "" {
		t.Error("Expected filesystem section")
	}
}

func TestGenerateUDPSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateUDPSection(d, duration)
	if result != "" {
		t.Error("Expected empty UDP section for no events")
	}
}

func TestGenerateUDPSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventUDPSend, LatencyNS: 1000000, Bytes: 512},
			{Type: events.EventUDPRecv, LatencyNS: 2000000, Bytes: 1024},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateUDPSection(d, duration)
	if result == "" {
		t.Error("Expected UDP section")
	}
}

func TestGenerateHTTPSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateHTTPSection(d, duration)
	if result != "" {
		t.Error("Expected empty HTTP section for no events")
	}
}

func TestGenerateHTTPSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com"},
			{Type: events.EventHTTPResp, LatencyNS: 10000000, Target: "http://example.com", Bytes: 2048},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateHTTPSection(d, duration)
	if result == "" {
		t.Error("Expected HTTP section")
	}
}

func TestGenerateCPUSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateCPUSection(d, duration)
	if result != "" {
		t.Error("Expected empty CPU section for no events")
	}
}

func TestGenerateCPUSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventSchedSwitch, LatencyNS: 1000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateCPUSection(d, duration)
	if result == "" {
		t.Error("Expected CPU section")
	}
}

func TestGenerateTCPStateSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPStateSection(d, duration)
	if result != "" {
		t.Error("Expected empty TCP state section for no events")
	}
}

func TestGenerateTCPStateSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTCPState, TCPState: 1, Target: "example.com:80"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPStateSection(d, duration)
	if result == "" {
		t.Error("Expected TCP state section")
	}
}

func TestGenerateMemorySection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateMemorySection(d, duration)
	if result != "" {
		t.Error("Expected empty memory section for no events")
	}
}

func TestGenerateMemorySection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventPageFault, Error: 1},
			{Type: events.EventOOMKill, Target: "process1", Bytes: 1048576, PID: 1234},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateMemorySection(d, duration)
	if result == "" {
		t.Error("Expected memory section")
	}
}

func TestGenerateIssuesSection(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, Error: 1},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
	}
	result := GenerateIssuesSection(d)
	if result == "" {
		t.Log("No issues detected (may be expected)")
	}
}

func TestGenerateSyscallSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSyscallSection(d, duration)
	if result != "" {
		t.Error("Expected empty syscall section for no events")
	}
}

func TestGenerateSyscallSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventExec, LatencyNS: 1000000, Target: "/bin/ls"},
			{Type: events.EventFork, PID: 1234, Target: "child"},
			{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 5},
			{Type: events.EventClose, Bytes: 5},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSyscallSection(d, duration)
	if result == "" {
		t.Error("Expected syscall section")
	}
}

func TestGenerateApplicationTracing_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateApplicationTracing(d, duration)
	if result == "" {
		t.Log("Empty application tracing is expected with no events")
	}
}

func TestGenerateApplicationTracing_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"},
			{Type: events.EventTCPSend, LatencyNS: 10000000, Bytes: 1024},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateApplicationTracing(d, duration)
	if result == "" {
		t.Error("Expected application tracing section")
	}
}

func TestCalculateThroughput(t *testing.T) {
	throughput := calculateThroughput(1024, 2*time.Second)
	if throughput != 512 {
		t.Errorf("Expected throughput 512, got %d", throughput)
	}

	throughput = calculateThroughput(1024, 0)
	if throughput != 0 {
		t.Errorf("Expected throughput 0 for zero duration, got %d", throughput)
	}
}

func TestGenerateResourceSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if result != "" {
		t.Error("Expected empty resource section for no events")
	}
}

func TestGenerateResourceSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 0, Error: 85, Bytes: 850000000},
			{Type: events.EventResourceLimit, TCPState: 1, Error: 92, Bytes: 460000000},
			{Type: events.EventResourceLimit, TCPState: 2, Error: 78, Bytes: 780000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if result == "" {
		t.Error("Expected resource section")
	}
	if !strings.Contains(result, "CPU") {
		t.Error("Expected CPU in resource section")
	}
	if !strings.Contains(result, "Memory") {
		t.Error("Expected Memory in resource section")
	}
	if !strings.Contains(result, "I/O") {
		t.Error("Expected I/O in resource section")
	}
}

func TestGenerateResourceSection_WarningLevel(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 0, Error: 85, Bytes: 850000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if !strings.Contains(result, "WARNING") {
		t.Error("Expected WARNING status in resource section")
	}
}

func TestGenerateResourceSection_CriticalLevel(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 1, Error: 92, Bytes: 460000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if !strings.Contains(result, "CRITICAL") {
		t.Error("Expected CRITICAL status in resource section")
	}
}

func TestGenerateResourceSection_EmergencyLevel(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 2, Error: 97, Bytes: 970000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if !strings.Contains(result, "EMERGENCY") {
		t.Error("Expected EMERGENCY status in resource section")
	}
}

// ---- GenerateCgroupScopeSection tests ----

func TestGenerateCgroupScopeSection_Empty(t *testing.T) {
	d := &mockDiagnostician{}
	if got := GenerateCgroupScopeSection(d); got != "" {
		t.Errorf("expected empty string for no events, got %q", got)
	}
}

func TestGenerateCgroupScopeSection_AllZero(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{CgroupID: 0},
			{CgroupID: 0},
		},
	}
	got := GenerateCgroupScopeSection(d)
	if !strings.Contains(got, "Cgroup Scope") {
		t.Error("expected 'Cgroup Scope' header")
	}
	if !strings.Contains(got, "cgroup_id=0") {
		t.Error("expected cgroup_id=0 report")
	}
	if !strings.Contains(got, "all events have cgroup_id=0") {
		t.Error("expected warning about all events having cgroup_id=0")
	}
}

func TestGenerateCgroupScopeSection_MultipleIDs(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{CgroupID: 1},
			{CgroupID: 2},
			{CgroupID: 1},
			nil, // nil events should be skipped
		},
	}
	got := GenerateCgroupScopeSection(d)
	if !strings.Contains(got, "Distinct non-zero cgroup_ids: 2") {
		t.Errorf("expected 2 distinct cgroup IDs, got: %q", got)
	}
	if !strings.Contains(got, "multiple cgroup_ids seen") {
		t.Error("expected warning about multiple cgroup IDs")
	}
}

func TestGenerateCgroupScopeSection_SingleNonZero(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{CgroupID: 42},
			{CgroupID: 42},
			{CgroupID: 42},
			{CgroupID: 42},
		},
	}
	got := GenerateCgroupScopeSection(d)
	if strings.Contains(got, "multiple cgroup_ids") {
		t.Error("should not warn about multiple cgroup IDs for single ID")
	}
	if !strings.Contains(got, "Top cgroup_ids") {
		t.Error("expected 'Top cgroup_ids' section")
	}
}

// ---- contains helper test ----

func TestContains(t *testing.T) {
	if !contains("CRITICAL error detected", "CRITICAL") {
		t.Error("expected contains=true for 'CRITICAL'")
	}
	if contains("all OK", "CRITICAL") {
		t.Error("expected contains=false for absent substring")
	}
}

// ---- determinePoolHealth tests ----

func TestDeterminePoolHealth_OK(t *testing.T) {
	stats := analyzer.PoolStats{
		ReuseRate:       0.9,
		MaxWaitTime:     100 * time.Millisecond,
		ExhaustedCount:  0,
		TotalAcquires:   100,
	}
	got := determinePoolHealth(stats)
	if got != "OK - Pool operating normally" {
		t.Errorf("expected OK, got %q", got)
	}
}

func TestDeterminePoolHealth_CriticalExhaustion(t *testing.T) {
	stats := analyzer.PoolStats{
		ExhaustedCount: 20,
		TotalAcquires:  100,
		ReuseRate:      0.9,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "CRITICAL") {
		t.Errorf("expected CRITICAL for >10%% exhaustion, got %q", got)
	}
}

func TestDeterminePoolHealth_WarningExhaustion(t *testing.T) {
	stats := analyzer.PoolStats{
		ExhaustedCount: 7,
		TotalAcquires:  100,
		ReuseRate:      0.9,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "WARNING") {
		t.Errorf("expected WARNING for 5-10%% exhaustion, got %q", got)
	}
}

func TestDeterminePoolHealth_LowReuseRate(t *testing.T) {
	stats := analyzer.PoolStats{
		ExhaustedCount: 0,
		ReuseRate:      0.3,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "reuse rate") {
		t.Errorf("expected WARNING for low reuse rate, got %q", got)
	}
}

func TestDeterminePoolHealth_HighWaitTime(t *testing.T) {
	stats := analyzer.PoolStats{
		ExhaustedCount: 0,
		ReuseRate:      0.9,
		MaxWaitTime:    2000 * time.Millisecond,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "wait times") {
		t.Errorf("expected WARNING for high wait times, got %q", got)
	}
}

// ---- determinePoolHealthFromSummary tests ----

func TestDeterminePoolHealthFromSummary_OK(t *testing.T) {
	s := tracker.PoolSummary{
		ReuseRate:      0.9,
		MaxWaitTime:    50 * time.Millisecond,
		ExhaustedCount: 0,
	}
	got := determinePoolHealthFromSummary(s)
	if got != "OK - Pool operating normally" {
		t.Errorf("expected OK, got %q", got)
	}
}

func TestDeterminePoolHealthFromSummary_Critical(t *testing.T) {
	s := tracker.PoolSummary{
		ExhaustedCount: 15,
		AcquireCount:   100,
		ReuseRate:      0.9,
	}
	got := determinePoolHealthFromSummary(s)
	if !strings.Contains(got, "CRITICAL") {
		t.Errorf("expected CRITICAL, got %q", got)
	}
}

func TestDeterminePoolHealthFromSummary_LowReuse(t *testing.T) {
	s := tracker.PoolSummary{
		ExhaustedCount: 0,
		ReuseRate:      0.2,
	}
	got := determinePoolHealthFromSummary(s)
	if !strings.Contains(got, "WARNING") {
		t.Errorf("expected WARNING for low reuse, got %q", got)
	}
}

// ---- GeneratePoolSection tests ----

func TestGeneratePoolSection_Empty(t *testing.T) {
	d := &mockDiagnostician{}
	if got := GeneratePoolSection(d, time.Second); got != "" {
		t.Errorf("expected empty string for no pool events, got %q", got)
	}
}

func TestGeneratePoolSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventPoolAcquire},
			{Type: events.EventPoolAcquire},
			{Type: events.EventPoolRelease},
		},
	}
	got := GeneratePoolSection(d, time.Second)
	if !strings.Contains(got, "Connection Pool") {
		t.Errorf("expected 'Connection Pool' header, got %q", got)
	}
	if !strings.Contains(got, "Total acquires: 2") {
		t.Errorf("expected 'Total acquires: 2', got %q", got)
	}
}

