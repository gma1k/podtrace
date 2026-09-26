package detector

import (
	"fmt"
	"strings"

	"github.com/gma1k/podtrace/internal/alerting"
)

// A typed issue, rather than a sentence.
type ID string

const (
	IDConnectionFailureRate ID = "net.connection_failure_rate"

	IDRTTSpikeRate ID = "net.rtt_spike_rate"

	IDResourceSaturation ID = "resource.saturation"

	IDL7ErrorRate ID = "l7.error_rate"

	IDL7LatencyDegraded ID = "l7.latency_degraded"

	IDDBAcquireSlow ID = "db.connection_acquire_slow"

	IDDBPoolSaturated ID = "db.pool_saturated"

	IDCPUContention ID = "cpu.contention"
)

// Registry is the documented issue vocabulary. Every ID the detector or the
// continuous inspections can emit appears here exactly once.
var Registry = []ID{
	IDConnectionFailureRate,
	IDRTTSpikeRate,
	IDResourceSaturation,
	IDL7ErrorRate,
	IDL7LatencyDegraded,
	IDDBAcquireSlow,
	IDDBPoolSaturated,
	IDCPUContention,
}

// Subject is what an issue is about.
type Subject struct {
	Namespace string
	Workload  string
	Container string

	Pod string

	Resource string
}

// Evidence is one measurement that made a rule fire.
type Evidence struct {
	Name      string
	Value     float64
	Threshold float64
	Unit      string
}

// Issue is one detected problem.
type Issue struct {
	ID       ID
	Severity alerting.AlertSeverity
	Subject  Subject
	Evidence []Evidence

	Remediation string

	Message string
}

func (i Issue) String() string { return i.Message }

func (i Issue) Key() string {
	return strings.Join([]string{
		string(i.ID), i.Subject.Namespace, i.Subject.Workload,
		i.Subject.Container, i.Subject.Pod, i.Subject.Resource,
	}, "|")
}

// Strings renders issues for consumers that still want plain text.
func Strings(issues []Issue) []string {
	out := make([]string, 0, len(issues))
	for _, issue := range issues {
		out = append(out, issue.Message)
	}
	return out
}

// evidence is a small constructor to keep detection sites readable.
func evidence(name string, value, threshold float64, unit string) Evidence {
	return Evidence{Name: name, Value: value, Threshold: threshold, Unit: unit}
}

// SeverityForUtilization is severityForUtilization, exported so the continuous
// inspections band a utilization gauge exactly as the diagnostic detector
// bands a utilization event.
func SeverityForUtilization(pct, warn, crit, emerg int) (alerting.AlertSeverity, bool) {
	return severityForUtilization(pct, warn, crit, emerg)
}

// SeverityLabel renders the uppercase word a message uses for a severity.
func SeverityLabel(s alerting.AlertSeverity) string { return severityLabel(s) }

// Evidence constructor, exported for rule definitions outside this package.
func NewEvidence(name string, value, threshold float64, unit string) Evidence {
	return evidence(name, value, threshold, unit)
}

// severityForUtilization maps a utilization percentage onto the product's one
// severity vocabulary.
func severityForUtilization(pct, warn, crit, emerg int) (alerting.AlertSeverity, bool) {
	switch {
	case pct >= emerg:
		return alerting.SeverityFatal, true
	case pct >= crit:
		return alerting.SeverityCritical, true
	case pct >= warn:
		return alerting.SeverityWarning, true
	default:
		return "", false
	}
}

// severityLabel renders the legacy uppercase word the resource message used,
// so the report text is unchanged.
func severityLabel(s alerting.AlertSeverity) string {
	switch s {
	case alerting.SeverityFatal:
		return "EMERGENCY"
	case alerting.SeverityCritical:
		return "CRITICAL"
	default:
		return "WARNING"
	}
}

func fmtRate(format string, args ...any) string { return fmt.Sprintf(format, args...) }
