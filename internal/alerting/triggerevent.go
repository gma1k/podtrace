package alerting

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The trigger-event contract is the wire format between the agent (which
// emits a Kubernetes Event when an alert fires) and the operator (which
// watches/lists those Events to fire "flight recorder" PodTraceSessions).
const (
	EventReasonAlert = "PodtraceAlert"

	EventComponent = "podtrace-agent"

	AnnotationAlertSource = "podtrace.io/alert-source"

	AnnotationAlertSeverity = "podtrace.io/alert-severity"
)

// Canonical alert Source tokens the trigger contract recognizes. Resource
// alerts already use the first two; OOM and error-rate are raised for the
// flight recorder.
const (
	AlertSourceResourceMonitor    = "resource_monitor"
	AlertSourceResourceMonitorBPF = "resource_monitor_bpf"
	AlertSourceOOM                = "oom"
	AlertSourceErrorRate          = "error_rate"
)

// BuildAlertEvent renders a core/v1.Event describing the alert, targeting the
// alert's pod as the involved object.
func BuildAlertEvent(alert *Alert, now time.Time) *corev1.Event {
	if alert == nil || alert.PodName == "" || alert.Namespace == "" {
		return nil
	}
	ts := metav1.NewTime(now)
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "podtrace-alert-",
			Namespace:    alert.Namespace,
			Annotations: map[string]string{
				AnnotationAlertSource:   alert.Source,
				AnnotationAlertSeverity: string(alert.Severity),
			},
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: alert.Namespace,
			Name:      alert.PodName,
		},
		Reason:         EventReasonAlert,
		Message:        alert.Title,
		Type:           corev1.EventTypeWarning,
		Source:         corev1.EventSource{Component: EventComponent},
		FirstTimestamp: ts,
		LastTimestamp:  ts,
		Count:          1,
	}
}
