package diagnose

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestSetTimeWindow_OverridesStartAndEnd(t *testing.T) {
	d := NewDiagnostician()
	start := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 1, 10, 5, 0, 0, time.UTC)
	d.SetTimeWindow(start, end)
	if !d.StartTime().Equal(start) {
		t.Errorf("StartTime = %v, want %v", d.StartTime(), start)
	}
	if !d.EndTime().Equal(end) {
		t.Errorf("EndTime = %v, want %v", d.EndTime(), end)
	}
}

func TestEventContexts_UnwrappedBuffer(t *testing.T) {
	d := NewDiagnostician()
	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, map[string]interface{}{"seq": "only"})

	contexts := d.EventContexts()
	if len(contexts) != 1 {
		t.Fatalf("EventContexts len = %d, want 1", len(contexts))
	}
	if contexts[0]["seq"] != "only" {
		t.Errorf("EventContexts = %v, want the single stored context", contexts[0])
	}
}

func TestEventContexts_WrappedBuffer(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.startTime = time.Now()

	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, map[string]interface{}{"seq": "first"})
	d.AddEventWithContext(&events.Event{Type: events.EventOOMKill}, map[string]interface{}{"seq": "second"})

	if !d.wrapped {
		t.Fatal("buffer should have wrapped after overflow with a sampled event")
	}
	contexts := d.EventContexts()
	if len(contexts) != 1 {
		t.Fatalf("EventContexts len = %d, want 1", len(contexts))
	}
	if contexts[0]["seq"] != "second" {
		t.Errorf("wrapped EventContexts should surface the newest context, got %v", contexts[0])
	}
}

func TestAddEventWithContext_PodCommTrackerReceivesNetworkEvent(t *testing.T) {
	d := NewDiagnosticianWithK8s("source-pod", "source-ns")
	ctx := map[string]interface{}{
		"target_pod":       "target-pod",
		"target_namespace": "target-ns",
	}
	d.AddEventWithContext(&events.Event{
		Type:      events.EventConnect,
		Target:    "10.0.0.5:443",
		Timestamp: uint64(time.Now().UnixNano()),
	}, ctx)

	summaries := d.podCommTracker.GetSummary()
	if len(summaries) != 1 {
		t.Fatalf("expected the pod communication tracker to record 1 pair, got %d", len(summaries))
	}
	if summaries[0].Target != "target-pod" {
		t.Errorf("recorded target = %q, want target-pod", summaries[0].Target)
	}
}

func TestGenerateReportWithContext_IncludesPodCommunication(t *testing.T) {
	d := NewDiagnosticianWithK8s("source-pod", "source-ns")
	ctx := map[string]interface{}{
		"target_pod":       "target-pod",
		"target_namespace": "target-ns",
	}
	d.AddEventWithContext(&events.Event{
		Type:      events.EventConnect,
		Target:    "10.0.0.5:443",
		Timestamp: uint64(time.Now().UnixNano()),
	}, ctx)
	d.Finish()

	report := d.GenerateReport()
	if !strings.Contains(report, "Pod-to-Pod Communication:") {
		t.Errorf("report should include the pod communication section, got:\n%s", report)
	}
	if !strings.Contains(report, "target-pod") {
		t.Errorf("report should mention the target pod, got:\n%s", report)
	}
}
