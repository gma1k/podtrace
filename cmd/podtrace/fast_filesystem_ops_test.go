package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

type fakeFastCounter struct {
	countErr error
	rows     []kernelagg.Row
	drainErr error
	drains   int
}

func (f *fakeFastCounter) CountFastFilesystemOps() error { return f.countErr }

func (f *fakeFastCounter) DrainFastFilesystemOps() ([]kernelagg.Row, error) {
	f.drains++
	return f.rows, f.drainErr
}

func fastRead(cgroup uint64, count uint64) kernelagg.Row {
	return kernelagg.Row{
		Key:   kernelagg.Key{CgroupID: cgroup, EventType: uint8(events.EventRead), Bucket: kernelagg.BucketIndex(50_000)},
		Value: kernelagg.Value{Count: count, SumNS: count * 50_000, Bytes: count * 4096},
	}
}

func withNoFastCounter(t *testing.T) {
	t.Helper()
	saved := fastFilesystemOps
	t.Cleanup(func() { fastFilesystemOps = saved })
	fastFilesystemOps = nil
}

func TestADiagnoseRunDrainsTheKernelsFastCountsOnce(t *testing.T) {
	withNoFastCounter(t)
	counter := &fakeFastCounter{rows: []kernelagg.Row{fastRead(7, 40)}}
	countFastFilesystemOps(counter)

	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(&events.Event{Type: events.EventRead, CgroupID: 7, LatencyNS: 5_000_000, Bytes: 10, K8s: &events.K8sMetadata{Namespace: "ns", PodName: "db-0"}})
	d.Finish()

	report := generateDiagnoseReport(d)
	if !strings.Contains(report, "Read operations: 41") || !strings.Contains(report, "under 1ms and counted in the kernel: 40") {
		t.Errorf("report does not count the kernel's fast reads:\n%s", report)
	}
	_ = generateDiagnoseReport(d)
	if counter.drains != 1 {
		t.Errorf("drained %d times; a second report would lose what the first drained", counter.drains)
	}
}

func TestEachPodsReportCountsOnlyItsOwnFastOperations(t *testing.T) {
	withNoFastCounter(t)
	countFastFilesystemOps(&fakeFastCounter{rows: []kernelagg.Row{fastRead(1, 10), fastRead(2, 30)}})

	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(&events.Event{Type: events.EventDNS, CgroupID: 1, K8s: &events.K8sMetadata{Namespace: "ns", PodName: "a"}})
	d.AddEvent(&events.Event{Type: events.EventDNS, CgroupID: 2, K8s: &events.K8sMetadata{Namespace: "ns", PodName: "b"}})
	d.Finish()

	report := generateDiagnoseReport(d)
	a, b, ok := strings.Cut(report, "Diagnosis: ns/b")
	if !ok {
		t.Fatalf("no per-pod sections:\n%s", report)
	}
	if !strings.Contains(a, "Read operations: 10") || !strings.Contains(b, "Read operations: 30") {
		t.Errorf("fast reads were not attributed to their pods:\n%s", report)
	}
}

func TestAFastCounterThatCannotStartIsNotDrained(t *testing.T) {
	withNoFastCounter(t)
	countFastFilesystemOps(&fakeFastCounter{countErr: errors.New("no map")})
	if fastFilesystemOps != nil {
		t.Error("a counter that failed to start was kept")
	}
	countFastFilesystemOps(struct{}{})
	if fastFilesystemOps != nil {
		t.Error("a tracer without the counter was given one")
	}
}

func TestAFailedDrainLeavesTheReportToTheEvents(t *testing.T) {
	withNoFastCounter(t)
	countFastFilesystemOps(&fakeFastCounter{drainErr: errors.New("map gone")})
	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(&events.Event{Type: events.EventRead, CgroupID: 7, LatencyNS: 5_000_000})
	d.Finish()
	if report := generateDiagnoseReport(d); !strings.Contains(report, "Read operations: 1 ") {
		t.Errorf("report = \n%s", report)
	}
}
