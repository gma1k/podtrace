package diagnose

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/events"
)

func sampledSession(t *testing.T) *Diagnostician {
	t.Helper()
	agg := NewDiagnostician()
	agg.maxEvents = 10
	agg.sampleUniform = rising()
	for i := range 40 {
		pod := "pod-a"
		if i%2 == 1 {
			pod = "pod-b"
		}
		agg.AddEvent(&events.Event{Type: events.EventDNS, K8s: &events.K8sMetadata{Namespace: "ns", PodName: pod}})
	}
	if agg.EventsSampledOut() == 0 {
		t.Fatal("the session buffer never sampled")
	}
	return agg
}

func TestAPerPodReportSaysItsEventsAreASampleOfTheSessionBuffer(t *testing.T) {
	agg := sampledSession(t)
	child := NewDiagnosticianWithK8s("pod-a", "ns")
	child.InheritSessionSampling(agg)
	for _, e := range agg.GetEvents() {
		if e.K8s.PodName == "pod-a" {
			child.AddEvent(e)
		}
	}
	got := report.GenerateSummarySection(child, time.Second)
	want := fmt.Sprintf("a session buffer that saw 40 events across all pods and sampled out %d,", agg.EventsSampledOut())
	if !strings.Contains(got, want) || !strings.Contains(got, "the counts below are a sample") {
		t.Errorf("per-pod summary does not carry the session's sampling notice:\n%s", got)
	}
	seen, out, ok := child.SessionSampling()
	if !ok || seen != 40 || out != agg.EventsSampledOut() {
		t.Errorf("SessionSampling() = %d, %d, %v", seen, out, ok)
	}
}

func TestAPerPodReportOfAnUnsampledSessionHasNoNotice(t *testing.T) {
	agg := NewDiagnostician()
	agg.AddEvent(&events.Event{Type: events.EventDNS})
	child := NewDiagnosticianWithK8s("pod-a", "ns")
	child.InheritSessionSampling(agg)
	child.AddEvent(&events.Event{Type: events.EventDNS})
	if _, _, ok := child.SessionSampling(); ok {
		t.Error("an unsampled session marked its pods as sampled")
	}
	if got := report.GenerateSummarySection(child, time.Second); strings.Contains(got, "sample") {
		t.Errorf("summary claims a sample:\n%s", got)
	}
}

func TestASizedDownBufferIsMentionedInAPerPodReportToo(t *testing.T) {
	withMemoryLimit(t, 4<<20, true)
	agg := sampledSession(t)
	child := NewDiagnosticianWithK8s("pod-a", "ns")
	child.InheritSessionSampling(agg)
	child.AddEvent(&events.Event{Type: events.EventDNS})
	if got := report.GenerateSummarySection(child, time.Second); !strings.Contains(got, "rather than") {
		t.Errorf("summary does not mention the sized-down buffer:\n%s", got)
	}
}
