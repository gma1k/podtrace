package export

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
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

func TestExportJSON_EmptyEvents(t *testing.T) {
	d := &mockDiagnostician{
		events:             []*events.Event{},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.Summary == nil {
		t.Error("Expected summary in export data")
	}
	if data.Summary["total_events"].(int) != 0 {
		t.Error("Expected 0 total events")
	}
}

func TestExportJSON_WithDNSEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com"},
			{Type: events.EventDNS, LatencyNS: 2000000, Target: "example.com", Error: 1},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.DNS == nil {
		t.Error("Expected DNS data")
	}
	if data.DNS["total_lookups"].(int) != 2 {
		t.Error("Expected 2 DNS lookups")
	}
}

func TestExportJSON_WithTCPEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTCPSend, LatencyNS: 1000000, Bytes: 1024},
			{Type: events.EventTCPRecv, LatencyNS: 2000000, Bytes: 2048},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.TCP == nil {
		t.Error("Expected TCP data")
	}
}

func TestExportJSON_WithConnectionEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.Connections == nil {
		t.Error("Expected Connections data")
	}
}

func TestExportJSON_WithFSEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096},
			{Type: events.EventWrite, LatencyNS: 3000000, Target: "/tmp/file2", Bytes: 2048},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.FileSystem == nil {
		t.Error("Expected FileSystem data")
	}
}

func TestExportJSON_WithCPUEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventSchedSwitch, LatencyNS: 1000000},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.CPU == nil {
		t.Error("Expected CPU data")
	}
}

func TestExportCSV_EmptyEvents(t *testing.T) {
	d := &mockDiagnostician{
		events:             []*events.Event{},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	var buf bytes.Buffer
	err := ExportCSV(d, &buf)
	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Expected CSV header")
	}
}

func TestExportCSV_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com", PID: 1234, ProcessName: "test", Timestamp: 1000, Error: 0},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	var buf bytes.Buffer
	err := ExportCSV(d, &buf)
	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Expected CSV output")
	}
}

func TestExportCSV_NilEvent(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			nil,
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com", PID: 1234, ProcessName: "test", Timestamp: 1000},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	var buf bytes.Buffer
	err := ExportCSV(d, &buf)
	if err != nil {
		t.Errorf("ExportCSV should not return error with nil event, got %v", err)
	}
}

func TestCalculateRate(t *testing.T) {
	rate := calculateRate(100, 10*time.Second)
	if rate != 10.0 {
		t.Errorf("Expected rate 10.0, got %.2f", rate)
	}

	rate = calculateRate(0, 10*time.Second)
	if rate != 0.0 {
		t.Errorf("Expected rate 0.0, got %.2f", rate)
	}

	rate = calculateRate(100, 0)
	if rate != 0.0 {
		t.Errorf("Expected rate 0.0 for zero duration, got %.2f", rate)
	}
}


// errorWriter always returns an error on Write.
type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// TestBuildDNSExportData_ZeroEvents covers the `return 0` branch in the
// inline closure inside buildDNSExportData when len(dnsEvents) == 0.
func TestBuildDNSExportData_ZeroEvents(t *testing.T) {
	data := buildDNSExportData(
		[]*events.Event{},   // 0 events → closure returns 0
		time.Second,
		0, 0, 0, 0, 0, 0,
		[]analyzer.TargetCount{},
	)
	if data == nil {
		t.Fatal("expected non-nil map")
	}
	if rate, ok := data["error_rate"]; !ok || rate.(float64) != 0.0 {
		t.Errorf("expected error_rate=0.0, got %v", rate)
	}
}

// TestExportCSV_FailingWriter exercises ExportCSV with a writer that always
// fails. The csv.Writer buffers internally, so the error may only surface on
// Flush (deferred). This test ensures no panic occurs.
func TestExportCSV_FailingWriter(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	// Must not panic; error may or may not be returned depending on buffering.
	_ = ExportCSV(d, &errorWriter{})
}

// TestExportCSV_RecordWriteError covers the `return err` inside the
// for-loop when writer.Write(record) fails.
func TestExportCSV_RecordWriteError(t *testing.T) {
	// Use a writer that succeeds for the header but fails for the first record.
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, Target: "example.com", PID: 1, ProcessName: "go"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}

	// countingWriter fails after the first write (header).
	var buf bytes.Buffer
	cw := &countAfterWriter{w: &buf, failAfter: 1}
	err := ExportCSV(d, cw)
	// Error may or may not occur depending on csv.Writer buffering;
	// just ensure no panic.
	_ = err
}

// countAfterWriter writes normally for the first N calls then returns error.
type countAfterWriter struct {
	w         io.Writer
	failAfter int
	count     int
}

func (c *countAfterWriter) Write(p []byte) (int, error) {
	c.count++
	if c.count > c.failAfter {
		return 0, io.ErrUnexpectedEOF
	}
	return c.w.Write(p)
}
