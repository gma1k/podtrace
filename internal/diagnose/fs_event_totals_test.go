package diagnose

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/events"
)

func slowWrite(cgroup uint64) *events.Event {
	return &events.Event{Type: events.EventWrite, CgroupID: cgroup, LatencyNS: 50_000_000, Bytes: 10}
}

func TestAFullBufferStillReportsEveryFilesystemOperation(t *testing.T) {
	d := NewDiagnosticianWithThresholds(10, 100, 10)
	d.maxEvents = 50
	d.sampleIntN = reject
	for i := 0; i < 500; i++ {
		d.AddEvent(slowWrite(1))
	}
	d.AddEvent(&events.Event{Type: events.EventDNS})

	if got := d.FilesystemEventTotals()[analyzer.FSEventKey{CgroupID: 1, Type: events.EventWrite}].Count; got != 500 {
		t.Fatalf("totals count %d writes, want 500", got)
	}
	section := report.GenerateFileSystemSection(d, time.Second)
	for _, want := range []string{"Write operations: 500", "Slow operations (>10.0ms): 500", "Total bytes transferred: 4.88 KB"} {
		if !strings.Contains(section, want) {
			t.Errorf("section = %q, want %q", section, want)
		}
	}
}

func TestADiagnosticianWithoutFilesystemEventsHasNoTotals(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	if got := d.FilesystemEventTotals(); got != nil {
		t.Errorf("totals = %v, want nil", got)
	}
}

func TestAPerPodDiagnosticianReportsItsShareOfTheWholeSession(t *testing.T) {
	agg := NewDiagnosticianWithThresholds(10, 100, 10)
	agg.maxEvents = 40
	agg.sampleIntN = reject
	for i := 0; i < 300; i++ {
		agg.AddEvent(slowWrite(1))
		agg.AddEvent(slowWrite(2))
	}
	kept := agg.GetEvents()
	var podA []*events.Event
	for _, e := range kept {
		if e.CgroupID == 1 {
			podA = append(podA, e)
		}
	}

	child := NewDiagnosticianWithK8sAndThresholds("pod-a", "ns", 10, 100, 10)
	child.InheritFilesystemEventTotals(agg.FilesystemEventTotals().Share(podA, analyzer.Kept(kept)))
	for _, e := range podA {
		child.AddEvent(e)
	}

	section := report.GenerateFileSystemSection(child, time.Second)
	if !strings.Contains(section, "Write operations: 300") {
		t.Errorf("section = %q, want pod-a's 300 writes", section)
	}
}

func TestTheJSONExportCountsEveryFilesystemOperationOfAFullBuffer(t *testing.T) {
	d := NewDiagnosticianWithThresholds(10, 100, 10)
	d.maxEvents = 20
	d.sampleIntN = reject
	for i := 0; i < 200; i++ {
		d.AddEvent(slowWrite(1))
	}
	d.Finish()
	fs := d.ExportJSON().FileSystem
	if fs["write_operations"] != uint64(200) || fs["slow_operations"] != 200 {
		t.Errorf("export = %v, want 200 writes, all slow", fs)
	}
}
