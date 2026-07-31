package agent

import (
	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

// emitTriggerAlert raises a flight-recorder alert for OOM-kill and
// resource-limit events. It is called from the router's post-enrichment,
// pre-filtering path (alongside emitCopyFailAlert) so it runs for every
// traced event with pod identity resolved, independent of whether the
// matched CR has an OTLP exporter or which filters it sets. The
// Kubernetes-Event sink then turns the alert into a trigger Event the
// operator watches.
//
// Error-rate is raised separately in the SDK exporter, where its
// rolling-window detector state lives.
func emitTriggerAlert(ev *events.Event) {
	if ev == nil {
		return
	}
	var source string
	var severity alerting.AlertSeverity
	var title string
	switch ev.Type {
	case events.EventOOMKill:
		source, severity, title = alerting.AlertSourceOOM, alerting.SeverityFatal, "container OOM-killed"
	case events.EventResourceLimit:
		sev, ok := resourceSeverityFromUtilization(ev.Error)
		if !ok {
			return
		}
		source, severity, title = alerting.AlertSourceResourceMonitor, sev, "resource limit threshold breached"
	default:
		return
	}
	if ev.K8s == nil || ev.K8s.PodName == "" || ev.K8s.Namespace == "" {
		return
	}
	mgr := alerting.GetGlobalManager()
	if mgr == nil {
		return
	}
	mgr.SendAlert(&alerting.Alert{
		Severity:  severity,
		Title:     title,
		Message:   title,
		Timestamp: ev.TimestampTime(),
		Source:    source,
		PodName:   ev.K8s.PodName,
		Namespace: ev.K8s.Namespace,
	})
}

// resourceSeverityFromUtilization maps a resource-limit event's utilization
// percent (carried in event.Error) to an alert severity using the same
// warn/crit/emerg thresholds the resource monitor applies, so trigger Events
// agree with the monitor's own alerts. Returns false below the warn floor.
func resourceSeverityFromUtilization(utilizationPercent int32) (alerting.AlertSeverity, bool) {
	util := int(utilizationPercent)
	switch {
	case util >= config.AlertEmergPct:
		return alerting.SeverityFatal, true
	case util >= config.AlertCritPct:
		return alerting.SeverityCritical, true
	case util >= config.AlertWarnPct:
		return alerting.SeverityWarning, true
	default:
		return "", false
	}
}
