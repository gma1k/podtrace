package agent

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/inspect"
	"github.com/gma1k/podtrace/internal/sanitize"
)

// Closing the loop from the continuous plane to the diagnostic one.
type alertSink interface {
	Send(ctx context.Context, alert *alerting.Alert) error
}

// issueAlerter raises an alert for each activated issue.
type issueAlerter struct {
	events     alertSink
	manager    *alerting.Manager
	resolvePod func(namespace, workload string) string
	now        func() time.Time
	logger     logr.Logger

	unresolvedPods prometheus.Counter
	undelivered    prometheus.Counter
}

func (a *issueAlerter) IssueActivated(issue detector.Issue) {
	pod := issue.Subject.Pod
	if pod == "" && a.resolvePod != nil {
		pod = a.resolvePod(issue.Subject.Namespace, issue.Subject.Workload)
	}
	if pod == "" {
		a.logger.Info("issue activated but no pod could be resolved; it will not start a session",
			"issue", issue.ID, "namespace", issue.Subject.Namespace,
			"workload", issue.Subject.Workload)
		if a.unresolvedPods != nil {
			a.unresolvedPods.Inc()
		}
		return
	}

	a.logger.Info("issue activated",
		"issue", issue.ID, "severity", issue.Severity,
		"namespace", issue.Subject.Namespace, "workload", issue.Subject.Workload,
		"pod", pod, "resource", issue.Subject.Resource)

	a.deliver(&alerting.Alert{
		Severity:        issue.Severity,
		Source:          alerting.AlertSourceIssue,
		Namespace:       issue.Subject.Namespace,
		PodName:         pod,
		Title:           sanitize.Terminal(issue.Message),
		Message:         sanitize.Terminal(issue.Message),
		Timestamp:       a.now(),
		ErrorCode:       string(issue.ID),
		Recommendations: []string{sanitize.Terminal(issue.Remediation)},
		Context:         issueContext(issue),
	})
}

// deliver routes one issue alert so that exactly one Kubernetes Event results.
func (a *issueAlerter) deliver(alert *alerting.Alert) {
	managerLive := a.manager != nil && a.manager.IsEnabled()

	if managerLive && config.AlertEventsEnabled {
		a.manager.SendAlert(alert)
		return
	}

	// Otherwise the manager cannot produce the Event the trigger contract
	// needs, so write it ourselves.
	if a.events != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.events.Send(ctx, alert); err != nil {
			a.logger.Error(err, "could not write the issue trigger Event; this issue "+
				"cannot start a session",
				"issue", alert.ErrorCode, "namespace", alert.Namespace, "pod", alert.PodName)
			if a.undelivered != nil {
				a.undelivered.Inc()
			}
		}
	} else if a.undelivered != nil {
		a.undelivered.Inc()
	}

	if managerLive {
		a.manager.SendAlert(alert)
	}
}

func (a *issueAlerter) IssueCleared(issue detector.Issue) {
	a.logger.Info("issue cleared",
		"issue", issue.ID, "namespace", issue.Subject.Namespace,
		"workload", issue.Subject.Workload, "resource", issue.Subject.Resource)
}

// issueContext carries the evidence onto the alert so a consumer can see the
// measured values without re-running the query.
func issueContext(issue detector.Issue) map[string]interface{} {
	out := map[string]interface{}{
		"issue_id":  string(issue.ID),
		"namespace": issue.Subject.Namespace,
		"workload":  issue.Subject.Workload,
	}
	if issue.Subject.Container != "" {
		out["container"] = issue.Subject.Container
	}
	if issue.Subject.Resource != "" {
		out["resource"] = issue.Subject.Resource
	}
	for _, ev := range issue.Evidence {
		out[ev.Name] = ev.Value
		if ev.Threshold != 0 {
			out[ev.Name+"_threshold"] = ev.Threshold
		}
	}
	return out
}

// enricherPodResolver adapts the enricher to the resolver the alerter needs.
func enricherPodResolver(e *PodEnricher) func(string, string) string {
	if e == nil {
		return nil
	}
	return func(namespace, workload string) string {
		pod, _ := e.PodFor(namespace, workload)
		return pod
	}
}

// inspectionThresholds reads the configured thresholds.
func inspectionThresholds() inspect.Thresholds {
	return inspect.Thresholds{
		ErrorRatePercent:     config.InspectionErrorRatePercent,
		MinRequestsPerSecond: config.InspectionMinRequestsPerSecond,
		MeanLatency:          config.InspectionMeanLatency,
		UtilizationWarn:      config.AlertWarnPct,
		UtilizationCritical:  config.AlertCritPct,
		UtilizationEmergency: config.AlertEmergPct,
		HoldTime:             config.InspectionsHoldTime,
	}
}

// buildInspectionEngine constructs the engine, or nil when inspections are
// off.
func buildInspectionEngine(metrics *Metrics, sink inspect.FamilySource, resolvePod func(string, string) string, events alertSink, logger logr.Logger) (*inspect.Engine, error) {
	if !config.InspectionsEnabled {
		return nil, nil
	}

	var alerter *issueAlerter
	if config.InspectionsAlerts {
		alerter = &issueAlerter{
			events:         events,
			manager:        alerting.GetGlobalManager(),
			resolvePod:     resolvePod,
			now:            time.Now,
			logger:         logger,
			unresolvedPods: metrics.IssuePodUnresolved,
			undelivered:    metrics.IssueAlertUndelivered,
		}
		if events == nil {
			logger.Info("inspection alerts are on but no Event writer is available; " +
				"issues will be graphed and will not start sessions")
		}
	}

	var observer inspect.Observer
	if alerter != nil {
		observer = alerter
	}

	return inspect.New(inspect.Options{
		Source:     sink,
		Registerer: metrics.Registerer(),
		Thresholds: inspectionThresholds(),
		Observer:   observer,
		Budget:     config.InspectionsBudget,
	})
}

// runInspections evaluates the rules on an interval.
func runInspections(ctx context.Context, engine *inspect.Engine, logger logr.Logger) error {
	if engine == nil {
		return nil
	}
	logger.Info("continuous inspections enabled",
		"interval", config.InspectionsInterval,
		"alerts", config.InspectionsAlerts,
		"budget", config.InspectionsBudget)

	ticker := time.NewTicker(config.InspectionsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			activated, err := engine.Evaluate()
			if err != nil {
				logger.Error(err, "inspection pass could not gather metrics fully")
			}
			for _, issue := range activated {
				logger.V(1).Info("inspection issue", "issue", issue.ID, "message", issue.Message)
			}
		}
	}
}
