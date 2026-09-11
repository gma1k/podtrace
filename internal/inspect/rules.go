package inspect

import (
	"fmt"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

const (
	familyL7Requests  = "podtrace_workload_l7_requests_total"
	familyL7Duration  = "podtrace_workload_l7_request_duration_seconds"
	familyUtilization = "podtrace_workload_resource_utilization_percent"
	familyAcquire     = "podtrace_workload_db_connection_acquire_seconds"
)

// RuleFamilies is every family the built-in rules read, and nothing else.
func RuleFamilies() []string {
	return []string{
		familyL7Requests,
		familyL7Duration,
		familyUtilization,
		familyAcquire,
	}
}

// Thresholds is the tunable part of the rule set.
type Thresholds struct {
	ErrorRatePercent float64

	MinRequestsPerSecond float64

	MeanLatency time.Duration

	UtilizationWarn      int
	UtilizationCritical  int
	UtilizationEmergency int

	AcquireMean time.Duration

	HoldTime time.Duration

	HoldTimes map[detector.ID]time.Duration
}

// unset reports whether no threshold was configured at all, so New can fill
// in the shipped defaults.
func (t Thresholds) unset() bool {
	return t.ErrorRatePercent == 0 &&
		t.MinRequestsPerSecond == 0 &&
		t.MeanLatency == 0 &&
		t.UtilizationWarn == 0 &&
		t.UtilizationCritical == 0 &&
		t.UtilizationEmergency == 0 &&
		t.AcquireMean == 0 &&
		t.HoldTime == 0 &&
		len(t.HoldTimes) == 0
}

// holdTimeFor returns how long a rule's condition must hold before its issue
// activates: the rule's own default unless overridden.
func (t Thresholds) holdTimeFor(rule Rule) time.Duration {
	if override, ok := t.HoldTimes[rule.ID]; ok && override > 0 {
		return override
	}
	if t.HoldTime > 0 {
		return t.HoldTime
	}
	return rule.For
}

// Rule is one continuous inspection.
type Rule struct {
	ID detector.ID

	For time.Duration

	Query string

	Eval func(w Window, t Thresholds) []detector.Issue
}

// DefaultThresholds are the shipped defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		ErrorRatePercent:     5,
		MinRequestsPerSecond: 0.1,
		MeanLatency:          time.Second,
		UtilizationWarn:      80,
		UtilizationCritical:  90,
		UtilizationEmergency: 95,
		AcquireMean:          100 * time.Millisecond,
	}
}

// Rules returns the built-in rule set.
func Rules() []Rule {
	return []Rule{
		errorRateRule(),
		latencyRule(),
		saturationRule(),
		acquireLatencyRule(),
	}
}

func subjectOf(s Sample) detector.Subject {
	return detector.Subject{
		Namespace: s.Namespace,
		Workload:  s.Workload,
		Container: s.Container,
	}
}

// errorRateRule fires on the error ratio of application-layer requests.
func errorRateRule() Rule {
	return Rule{
		ID:  detector.IDL7ErrorRate,
		For: 2 * time.Minute,
		Query: `100 * sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total{outcome="error"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}
			interval := w.Interval()

			type totals struct {
				sample   Sample
				requests float64
				errors   float64
			}
			byWorkload := map[string]*totals{}
			for _, d := range w.Deltas(familyL7Requests) {
				if d.Reset {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &totals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.requests += d.Value
				if d.Sample.Label("outcome") == "error" {
					agg.errors += d.Value
				}
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				if agg.requests == 0 {
					continue
				}
				perSecond := agg.requests / interval.Seconds()
				if perSecond < t.MinRequestsPerSecond {
					continue
				}
				ratio := agg.errors / agg.requests * 100
				if ratio <= t.ErrorRatePercent {
					continue
				}
				issues = append(issues, detector.Issue{
					ID:       detector.IDL7ErrorRate,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: agg.sample.Namespace,
						Workload:  agg.sample.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("error_rate", ratio, t.ErrorRatePercent, "%"),
						detector.NewEvidence("errors", agg.errors, 0, "count"),
						detector.NewEvidence("requests", agg.requests, 0, "count"),
						detector.NewEvidence("request_rate", perSecond, t.MinRequestsPerSecond, "/s"),
					},
					Remediation: "Check the workload's own logs first, then the service map " +
						"for a failing dependency; a session on this workload captures the " +
						"failing requests with their status codes.",
					Message: fmt.Sprintf("High application error rate for %s/%s: %.1f%% of %.0f requests (threshold: %.1f%%)",
						agg.sample.Namespace, agg.sample.Workload, ratio, agg.requests, t.ErrorRatePercent),
				})
			}
			return issues
		},
	}
}

// latencyRule fires on the mean request duration over the interval.
func latencyRule() Rule {
	return Rule{
		ID:  detector.IDL7LatencyDegraded,
		For: 3 * time.Minute,
		Query: `sum by (namespace, workload) (rate(podtrace_workload_l7_request_duration_seconds_sum[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_l7_request_duration_seconds_count[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}

			type totals struct {
				sample Sample
				count  uint64
				sum    float64
			}
			byWorkload := map[string]*totals{}
			for _, d := range w.Deltas(familyL7Duration) {
				if d.Reset || d.Count == 0 {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &totals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.count += d.Count
				agg.sum += d.Sum
			}

			threshold := t.MeanLatency.Seconds()
			var issues []detector.Issue
			for _, agg := range byWorkload {
				mean := agg.sum / float64(agg.count)
				if mean <= threshold {
					continue
				}
				issues = append(issues, detector.Issue{
					ID:       detector.IDL7LatencyDegraded,
					Severity: alerting.SeverityWarning,
					Subject: detector.Subject{
						Namespace: agg.sample.Namespace,
						Workload:  agg.sample.Workload,
					},
					Evidence: []detector.Evidence{
						detector.NewEvidence("mean_duration", mean, threshold, "s"),
						detector.NewEvidence("requests", float64(agg.count), 0, "count"),
					},
					Remediation: "Compare the workload's own duration against its egress edges " +
						"on the service map: if a dependency moved with it, the cause is " +
						"downstream; if it did not, profile the workload itself.",
					Message: fmt.Sprintf("Degraded request latency for %s/%s: %.0fms mean over %d requests (threshold: %.0fms)",
						agg.sample.Namespace, agg.sample.Workload,
						mean*1000, agg.count, threshold*1000),
				})
			}
			return issues
		},
	}
}

// saturationRule fires on a container approaching a resource limit.
func saturationRule() Rule {
	return Rule{
		ID:    detector.IDResourceSaturation,
		For:   time.Minute,
		Query: `max by (namespace, workload, resource) (podtrace_workload_resource_utilization_percent)`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			var issues []detector.Issue
			for _, s := range w.Gauges(familyUtilization) {
				pct := int(s.Value)
				severity, firing := detector.SeverityForUtilization(pct,
					t.UtilizationWarn, t.UtilizationCritical, t.UtilizationEmergency)
				if !firing {
					continue
				}
				resource := s.Label("resource")
				subject := subjectOf(s)
				subject.Pod = s.Pod
				subject.Resource = resource
				issues = append(issues, detector.Issue{
					ID:       detector.IDResourceSaturation,
					Severity: severity,
					Subject:  subject,
					Evidence: []detector.Evidence{
						detector.NewEvidence("utilization", s.Value,
							float64(t.UtilizationWarn), "%"),
					},
					Remediation: "Raise the container's limit for this resource, or reduce what " +
						"the workload asks of it; saturation here shows up as latency everywhere else.",
					Message: fmt.Sprintf("Resource limit %s: %s/%s %s at %d%% utilization (threshold: %d%% warning, %d%% critical, %d%% emergency)",
						detector.SeverityLabel(severity), s.Namespace, s.Workload, resource, pct,
						t.UtilizationWarn, t.UtilizationCritical, t.UtilizationEmergency),
				})
			}
			return issues
		},
	}
}

// acquireLatencyRule fires when callers are spending real time getting a
// database connection before their query can start.
func acquireLatencyRule() Rule {
	return Rule{
		ID:  detector.IDDBAcquireSlow,
		For: 2 * time.Minute,
		Query: `sum by (namespace, workload) (rate(podtrace_workload_db_connection_acquire_seconds_sum[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_db_connection_acquire_seconds_count[5m]))`,
		Eval: func(w Window, t Thresholds) []detector.Issue {
			if !w.Ready() {
				return nil
			}

			type totals struct {
				sample Sample
				count  uint64
				sum    float64
			}
			byWorkload := map[string]*totals{}
			for _, d := range w.Deltas(familyAcquire) {
				if d.Reset || d.Count == 0 {
					continue
				}
				key := d.Sample.Namespace + "/" + d.Sample.Workload
				agg, ok := byWorkload[key]
				if !ok {
					agg = &totals{sample: d.Sample}
					byWorkload[key] = agg
				}
				agg.count += d.Count
				agg.sum += d.Sum
			}

			var issues []detector.Issue
			for _, agg := range byWorkload {
				mean := time.Duration(agg.sum / float64(agg.count) * float64(time.Second))
				if mean < t.AcquireMean {
					continue
				}
				s := agg.sample
				issues = append(issues, detector.Issue{
					ID:       detector.IDDBAcquireSlow,
					Severity: alerting.SeverityWarning,
					Subject:  subjectOf(s),
					Evidence: []detector.Evidence{
						detector.NewEvidence("mean_acquire_time", mean.Seconds(),
							t.AcquireMean.Seconds(), "s"),
						detector.NewEvidence("waiting_acquisitions", float64(agg.count), 0, ""),
					},
					Remediation: "Check SetMaxOpenConns and SetMaxIdleConns together: a low " +
						"maximum queues callers, while a low idle count makes them re-establish " +
						"connections they could have reused. Both show up here. Compare with the " +
						"application's own sql.DBStats to tell which.",
					Message: fmt.Sprintf("Slow database connection acquisition: %s/%s spent a mean of %s across %d acquisitions, queueing or reconnecting (threshold: %s)",
						s.Namespace, s.Workload, mean.Round(time.Millisecond), agg.count,
						t.AcquireMean.Round(time.Millisecond)),
				})
			}
			return issues
		},
	}
}
