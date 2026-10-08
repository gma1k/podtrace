package report

import (
	"fmt"
	"strings"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/sanitize"
)

// Trigger is the continuous-inspection issue that started a session.
type Trigger struct {
	IssueID  string
	Severity string
	Pod      string
	At       string
	Reason   string
}

// issueSections names the report section that holds each issue's evidence.
var issueSections = map[detector.ID]string{
	detector.IDConnectionFailureRate: "Connection Statistics",
	detector.IDRTTSpikeRate:          "TCP Statistics",
	detector.IDResourceSaturation:    "Resource Limits Statistics",
	detector.IDL7ErrorRate:           "HTTP Statistics",
	detector.IDL7LatencyDegraded:     "HTTP Statistics",
	detector.IDDBAcquireSlow:         "Connection Pool Statistics",
	detector.IDDBPoolSaturated:       "Connection Pool Statistics",
	detector.IDCPUContention:         "CPU Statistics",
	detector.IDDNSSlowLookupRate:     "DNS Statistics",
	detector.IDFSSlowOperations:      "File System Statistics",
	detector.IDDNSFailureRate:        "DNS Statistics",
}

// GenerateTriggerSection opens the report of a session an issue started: what
// fired, what the agent measured, and whether this session saw it too. It
// returns "" when no issue started the session.
func GenerateTriggerSection(t Trigger, d Diagnostician) string {
	if t.IssueID == "" {
		return ""
	}
	id := detector.ID(t.IssueID)

	var b strings.Builder
	fmt.Fprintf(&b, "=== Started by issue %s ===\n\n", sanitize.Terminal(t.IssueID))
	var seen string
	switch {
	case sessionDetected(id, d):
		seen = "detected it too; see Potential Issues Detected"
	case sessionMeasures(id):
		seen = "did not detect it; the condition may have cleared before collection began"
	default:
		seen = "does not raise this issue itself; the agent's measurement above is the evidence"
	}

	for _, line := range []struct{ label, value string }{
		{"Severity", t.Severity},
		{"Pod", t.Pod},
		{"Fired at", t.At},
		{"Agent measured", t.Reason},
		{"This capture", seen},
		{"Look first at", issueSections[id]},
	} {
		if line.value != "" {
			fmt.Fprintf(&b, "  %-15s %s\n", line.label+":", sanitize.Terminal(line.value))
		}
	}
	b.WriteString("\n")
	return b.String()
}

// sessionMeasures reports whether a session's own detector can raise id.
func sessionMeasures(id detector.ID) bool {
	for _, known := range detector.SessionIDs {
		if known == id {
			return true
		}
	}
	return false
}

func sessionDetected(id detector.ID, d Diagnostician) bool {
	if d == nil || !sessionMeasures(id) {
		return false
	}
	for _, issue := range detector.DetectIssues(d.GetEvents(), d.ErrorRateThreshold(), d.RTTSpikeThreshold()) {
		if issue.ID == id {
			return true
		}
	}
	return false
}
