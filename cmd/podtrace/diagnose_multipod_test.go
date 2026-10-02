package main

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose"
	diagnosereport "github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/events"
)

func eventForPod(ns, pod string) *events.Event {
	return &events.Event{
		Type: events.EventDNS,
		K8s:  &events.K8sMetadata{Namespace: ns, PodName: pod},
	}
}

func TestGenerateDiagnoseReport_PerPodSections(t *testing.T) {
	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(eventForPod("ns", "pod-a"))
	d.AddEvent(eventForPod("ns", "pod-b"))
	d.Finish()

	report := generateDiagnoseReport(d)
	if !strings.Contains(report, "Diagnosis: ns/pod-a") {
		t.Errorf("report missing per-pod section for ns/pod-a:\n%s", report)
	}
	if !strings.Contains(report, "Diagnosis: ns/pod-b") {
		t.Errorf("report missing per-pod section for ns/pod-b:\n%s", report)
	}
}

func TestGenerateDiagnoseReport_SinglePodUnchanged(t *testing.T) {
	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(eventForPod("ns", "only-pod"))
	d.AddEvent(eventForPod("ns", "only-pod"))
	d.Finish()

	report := generateDiagnoseReport(d)
	if strings.Contains(report, "Diagnosis: ns/only-pod") {
		t.Errorf("single-pod report should not add per-pod section headers:\n%s", report)
	}
}

func TestATriggeredSessionReportOpensWithItsIssue(t *testing.T) {
	saved := sessionTrigger
	t.Cleanup(func() { sessionTrigger = saved })
	sessionTrigger = diagnosereport.Trigger{IssueID: "l7.error_rate", Pod: "ns/only-pod"}

	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(eventForPod("ns", "only-pod"))
	d.Finish()

	report := generateDiagnoseReport(d)
	if !strings.HasPrefix(report, "=== Started by issue l7.error_rate ===") {
		t.Errorf("report does not open with the triggering issue:\n%s", report)
	}
}
