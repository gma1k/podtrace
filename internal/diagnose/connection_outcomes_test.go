package diagnose

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/events"
)

func refusedTraffic(t *testing.T) *Diagnostician {
	t.Helper()
	d := NewDiagnostician()
	for i := 0; i < 3; i++ {
		d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 40_000, Target: "10.96.0.5:5432"})
		d.AddEvent(&events.Event{Type: events.EventConnectResult, Error: -111, Target: "10.96.0.5:5432"})
	}
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 40_000, Target: "10.96.0.6:80"})
	d.AddEvent(&events.Event{Type: events.EventConnectResult, Target: "10.96.0.6:80"})
	d.Finish()
	return d
}

func TestTheConnectionSectionCountsARefusalThatConnectReturnedZeroFor(t *testing.T) {
	d := refusedTraffic(t)
	section := report.GenerateConnectionSection(d, d.endTime.Sub(d.startTime))

	if !strings.Contains(section, "Failed connections: 3 of 4 attempts (75.0%)") {
		t.Errorf("section did not score three refusals out of four attempts:\n%s\n\n"+
			"connect() returns 0 once the SYN is queued, so a report that only reads its "+
			"return value says a database refusing every connection is healthy.", section)
	}
	if !strings.Contains(section, "Error -111: 3") {
		t.Errorf("the breakdown does not name ECONNREFUSED:\n%s", section)
	}
}

func TestTheExportScoresFailuresOverAttempts(t *testing.T) {
	data := refusedTraffic(t).ExportJSON()

	if got := data.Connections["attempts"]; got != 4 {
		t.Errorf("attempts = %v, want 4", got)
	}
	if got := data.Connections["failed"]; got != 3 {
		t.Errorf("failed = %v, want 3", got)
	}
	if got := data.Connections["failure_rate"]; got != 75.0 {
		t.Errorf("failure_rate = %v, want 75", got)
	}
	if got := data.Connections["total_connections"]; got != 4 {
		t.Errorf("total_connections = %v, want the 4 connect calls", got)
	}
}

func TestADiagnoseSessionFlagsAServiceThatRefusesEveryConnection(t *testing.T) {
	d := refusedTraffic(t)
	section := report.GenerateIssuesSection(d)

	if !strings.Contains(section, "connection failure rate") {
		t.Errorf("no connection-failure issue for 75%% refusals:\n%s", section)
	}
}

func TestSuccessfulConnectsAloneReportNoFailuresAndNoNaN(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 40_000, Target: "10.96.0.6:80"})
	d.Finish()

	section := report.GenerateConnectionSection(d, d.endTime.Sub(d.startTime))
	if !strings.Contains(section, "Failed connections: 0 of 0 attempts (0.0%)") {
		t.Errorf("a connect with no handshake result yet did not read as zero failures:\n%s", section)
	}
	if strings.Contains(section, "NaN") {
		t.Errorf("zero attempts produced NaN:\n%s", section)
	}
}

func TestFailuresOfOtherKindsAreNotConnectionFailures(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 40_000, Target: "10.96.0.6:80"})
	d.AddEvent(&events.Event{Type: events.EventConnectResult, Target: "10.96.0.6:80"})
	for i := 0; i < 5; i++ {
		d.AddEvent(&events.Event{Type: events.EventTCPSend, Error: -32, Target: "10.96.0.6:80"})
		d.AddEvent(&events.Event{Type: events.EventHTTPResp, Error: 500, Target: "/checkout"})
	}
	d.Finish()

	if section := report.GenerateIssuesSection(d); strings.Contains(section, "connection failure rate") {
		t.Errorf("broken pipes and HTTP 500s were scored as failed connections:\n%s\n\n"+
			"The one connection attempt succeeded. Counting every failed event as a "+
			"failed connect turns an application error into a network alarm.", section)
	}
}

func TestADiagnoseReportDoesNotCallADualStackFallbackAFailure(t *testing.T) {
	d := NewDiagnostician()
	for i := 0; i < 5; i++ {
		for j := 0; j < 8; j++ {
			d.AddEvent(&events.Event{Type: events.EventConnect, Error: -101, Target: "[2001:db8::1]:80"})
		}
		d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 40_000, Target: "142.250.1.1:80"})
		d.AddEvent(&events.Event{Type: events.EventConnectResult, Target: "142.250.1.1:80"})
	}
	d.Finish()

	if section := report.GenerateIssuesSection(d); strings.Contains(section, "connection failure rate") {
		t.Errorf("a pod whose every request succeeded over IPv4 was flagged:\n%s", section)
	}
	section := report.GenerateConnectionSection(d, d.endTime.Sub(d.startTime))
	if !strings.Contains(section, "Failed connections: 0 of 5 attempts") ||
		!strings.Contains(section, "No route for address family: 40") {
		t.Errorf("the section does not separate the fallback from real attempts:\n%s", section)
	}
}
