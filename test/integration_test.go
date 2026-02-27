//go:build integration
// +build integration

package test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/cri"
	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/events"
)

func TestDiagnostician_RealWorldScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	d := diagnose.NewDiagnostician()

	eventTypes := []events.EventType{
		events.EventDNS,
		events.EventConnect,
		events.EventTCPSend,
		events.EventTCPRecv,
		events.EventRead,
		events.EventWrite,
	}

	for i := 0; i < 100; i++ {
		eventType := eventTypes[i%len(eventTypes)]
		event := &events.Event{
			Type:      eventType,
			PID:       uint32(1000 + i%10),
			LatencyNS: uint64((i + 1) * 1000000), // 1ms to 100ms
			Target:    "example.com",
			Error:     0,
		}

		if i%10 == 0 {
			event.Error = 111
		}

		d.AddEvent(event)
	}

	d.Finish()

	report := d.GenerateReport()
	if report == "" {
		t.Error("Report should not be empty")
	}

	sections := []string{
		"Summary",
		"DNS Statistics",
		"TCP Statistics",
		"Connection Statistics",
	}

	for _, section := range sections {
		if !contains(report, section) {
			t.Errorf("Report should contain section '%s'", section)
		}
	}
}

func TestDiagnostician_ExportFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	d := diagnose.NewDiagnostician()

	for i := 0; i < 50; i++ {
		d.AddEvent(&events.Event{
			Type:      events.EventDNS,
			LatencyNS: uint64(i * 1000000),
			Target:    "example.com",
		})
	}

	d.Finish()

	jsonData := d.ExportJSON()
	if jsonData.Summary == nil {
		t.Error("JSON export should include summary")
	}

	var csvBuf []byte
	writer := &testWriter{data: &csvBuf}
	err := d.ExportCSV(writer)
	if err != nil {
		t.Errorf("CSV export should not fail: %v", err)
	}
	if len(csvBuf) == 0 {
		t.Error("CSV export should produce output")
	}
}

func TestDiagnostician_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	d := diagnose.NewDiagnostician()

	start := time.Now()
	for i := 0; i < 10000; i++ {
		d.AddEvent(&events.Event{
			Type:      events.EventDNS,
			LatencyNS: uint64(i * 1000000),
			Target:    "example.com",
		})
	}
	addDuration := time.Since(start)

	if addDuration > 1*time.Second {
		t.Errorf("Adding 10000 events took too long: %v", addDuration)
	}

	d.Finish()

	start = time.Now()
	_ = d.GenerateReport()
	reportDuration := time.Since(start)

	if reportDuration > 5*time.Second {
		t.Errorf("Generating report took too long: %v", reportDuration)
	}
}

// TestCRIResolver_ConnectToSocket verifies that the CRI resolver can connect to
// a real CRI socket on the host. The test is skipped when no socket is available,
// so it is safe to run in any environment.
func TestCRIResolver_ConnectToSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CRI integration test in short mode")
	}

	// Prefer an explicitly configured endpoint.
	endpoint := os.Getenv("PODTRACE_CRI_ENDPOINT")
	if endpoint == "" {
		// Pick the first candidate socket that actually exists.
		for _, ep := range cri.DefaultCandidateEndpoints() {
			path := strings.TrimPrefix(ep, "unix://")
			if _, err := os.Stat(path); err == nil {
				endpoint = ep
				break
			}
		}
	}
	if endpoint == "" {
		t.Skip("No CRI socket found; skipping CRI integration test")
	}

	resolver, err := cri.NewResolverWithEndpoint(endpoint)
	if err != nil {
		t.Skipf("Could not connect to CRI endpoint %q: %v", endpoint, err)
	}
	defer resolver.Close()

	if got := resolver.Endpoint(); got != endpoint {
		t.Errorf("Endpoint() = %q, want %q", got, endpoint)
	}

	// ResolveContainer with an empty ID must return a well-typed error, not panic.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = resolver.ResolveContainer(ctx, "")
	if err == nil {
		t.Error("expected error for empty container ID, got nil")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}

type testWriter struct {
	data *[]byte
}

func (w *testWriter) Write(p []byte) (n int, err error) {
	*w.data = append(*w.data, p...)
	return len(p), nil
}
