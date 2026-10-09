package alerting

import (
	"strings"
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

	AnnotationIssueID  = "podtrace.io/issue-id"
	AnnotationWorkload = "podtrace.io/workload"

	AnnotationLikelyCauses = "podtrace.io/likely-causes"
)

// Canonical alert Source tokens the trigger contract recognizes. Resource
// alerts already use the first two; OOM and error-rate are raised for the
// flight recorder.
const (
	AlertSourceResourceMonitor    = "resource_monitor"
	AlertSourceResourceMonitorBPF = "resource_monitor_bpf"
	AlertSourceOOM                = "oom"
	AlertSourceErrorRate          = "error_rate"

	AlertSourceIssue = "issue"
)

// BuildAlertEvent renders a core/v1.Event describing the alert, targeting the
// alert's pod as the involved object.
func BuildAlertEvent(alert *Alert, now time.Time) *corev1.Event {
	if alert == nil || alert.PodName == "" || alert.Namespace == "" {
		return nil
	}
	ts := metav1.NewTime(now)
	annotations := map[string]string{
		AnnotationAlertSource:   alert.Source,
		AnnotationAlertSeverity: string(alert.Severity),
	}
	if alert.Source == AlertSourceIssue {
		if alert.ErrorCode != "" {
			annotations[AnnotationIssueID] = alert.ErrorCode
		}
		if workload, ok := alert.Context["workload"].(string); ok && workload != "" {
			annotations[AnnotationWorkload] = workload
		}
	}
	message := alert.Title
	if causes := likelyCauses(alert); causes != "" {
		annotations[AnnotationLikelyCauses] = causes
		message += ". Likely cause: " + causes
	}
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "podtrace-alert-",
			Namespace:    alert.Namespace,
			Annotations:  annotations,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: alert.Namespace,
			Name:      alert.PodName,
		},
		Reason:         EventReasonAlert,
		Message:        message,
		Type:           corev1.EventTypeWarning,
		Source:         corev1.EventSource{Component: EventComponent},
		FirstTimestamp: ts,
		LastTimestamp:  ts,
		Count:          1,
	}
}

// likelyCauses reads an issue alert's likely causes. Only the Event carries
// them, not the title: the title is what deduplication keys on, and a cause
// appearing must not make an issue look new.
func likelyCauses(alert *Alert) string {
	if alert.Source != AlertSourceIssue {
		return ""
	}
	causes, _ := alert.Context["likely_causes"].([]string)
	return strings.Join(causes, "; ")
}
