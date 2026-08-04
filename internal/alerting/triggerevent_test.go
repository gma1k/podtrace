package alerting

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestBuildAlertEvent_RejectsAlertsWithoutPodIdentity(t *testing.T) {
	at := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	cases := map[string]*Alert{
		"nil alert":                 nil,
		"no pod name":               {Severity: SeverityFatal, Source: AlertSourceOOM, Namespace: "prod"},
		"no namespace":              {Severity: SeverityFatal, Source: AlertSourceOOM, PodName: "checkout-7f"},
		"neither pod nor namespace": {Severity: SeverityFatal, Source: AlertSourceOOM},
	}
	for name, alert := range cases {
		t.Run(name, func(t *testing.T) {
			if ev := BuildAlertEvent(alert, at); ev != nil {
				t.Errorf("expected no Event, got %+v", ev)
			}
		})
	}
}

func TestBuildAlertEvent_PopulatesTriggerContract(t *testing.T) {
	at := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	ev := BuildAlertEvent(&Alert{
		Severity:  SeverityCritical,
		Source:    AlertSourceResourceMonitor,
		Title:     "resource limit threshold breached",
		Message:   "resource limit threshold breached",
		PodName:   "checkout-7f",
		Namespace: "prod",
		Timestamp: at,
	}, at)
	if ev == nil {
		t.Fatal("expected an Event for a pod-bearing alert")
		return
	}
	if ev.Name != "" || ev.GenerateName != "podtrace-alert-" {
		t.Errorf("name = %q, generateName = %q; want server-side generated name", ev.Name, ev.GenerateName)
	}
	if ev.Namespace != "prod" {
		t.Errorf("namespace = %q, want prod", ev.Namespace)
	}
	if ev.Reason != EventReasonAlert {
		t.Errorf("reason = %q, want %q", ev.Reason, EventReasonAlert)
	}
	if ev.Type != corev1.EventTypeWarning {
		t.Errorf("type = %q, want %q", ev.Type, corev1.EventTypeWarning)
	}
	if ev.Source.Component != EventComponent {
		t.Errorf("source component = %q, want %q", ev.Source.Component, EventComponent)
	}
	if ev.Message != "resource limit threshold breached" {
		t.Errorf("message = %q", ev.Message)
	}
	if ev.InvolvedObject.Kind != "Pod" || ev.InvolvedObject.Namespace != "prod" || ev.InvolvedObject.Name != "checkout-7f" {
		t.Errorf("involvedObject = %+v", ev.InvolvedObject)
	}
	if got := ev.Annotations[AnnotationAlertSource]; got != AlertSourceResourceMonitor {
		t.Errorf("%s = %q, want %q", AnnotationAlertSource, got, AlertSourceResourceMonitor)
	}
	if got := ev.Annotations[AnnotationAlertSeverity]; got != string(SeverityCritical) {
		t.Errorf("%s = %q, want %q", AnnotationAlertSeverity, got, SeverityCritical)
	}
	if !ev.FirstTimestamp.Time.Equal(at) || !ev.LastTimestamp.Time.Equal(at) {
		t.Errorf("timestamps = %v / %v, want %v", ev.FirstTimestamp, ev.LastTimestamp, at)
	}
	if ev.Count != 1 {
		t.Errorf("count = %d, want 1", ev.Count)
	}
}

func TestBuildAlertEvent_CarriesEverySourceToken(t *testing.T) {
	at := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	for _, source := range []string{
		AlertSourceResourceMonitor,
		AlertSourceResourceMonitorBPF,
		AlertSourceOOM,
		AlertSourceErrorRate,
	} {
		t.Run(source, func(t *testing.T) {
			ev := BuildAlertEvent(&Alert{
				Severity:  SeverityCritical,
				Source:    source,
				Title:     "t",
				PodName:   "p",
				Namespace: "ns",
				Timestamp: at,
			}, at)
			if ev == nil {
				t.Fatal("expected an Event")
				return
			}
			if got := ev.Annotations[AnnotationAlertSource]; got != source {
				t.Errorf("%s = %q, want %q", AnnotationAlertSource, got, source)
			}
		})
	}
}
