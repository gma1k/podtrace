package main

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/events"
)

func writeForPod(pod string, cgroup uint64) *events.Event {
	return &events.Event{
		Type:      events.EventWrite,
		CgroupID:  cgroup,
		LatencyNS: 20_000_000,
		K8s:       &events.K8sMetadata{Namespace: "ns", PodName: pod},
	}
}

func TestEachPodSectionCountsItsOwnFilesystemOperationsOnce(t *testing.T) {
	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	for i := 0; i < 3; i++ {
		d.AddEvent(writeForPod("pod-a", 11))
	}
	d.AddEvent(writeForPod("pod-b", 22))
	d.Finish()

	got := diagnosisByPod(d)
	a := strings.Index(got, "Diagnosis: ns/pod-a")
	b := strings.Index(got, "Diagnosis: ns/pod-b")
	if a < 0 || b < a {
		t.Fatalf("report has no per-pod sections:\n%s", got)
	}
	if !strings.Contains(got[a:b], "Write operations: 3 ") {
		t.Errorf("pod-a section does not count its 3 writes once:\n%s", got[a:b])
	}
	if !strings.Contains(got[b:], "Write operations: 1 ") {
		t.Errorf("pod-b section does not count its 1 write once:\n%s", got[b:])
	}
}
