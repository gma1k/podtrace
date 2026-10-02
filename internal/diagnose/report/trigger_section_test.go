package report

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/redactor"
)

func failingConnects() *mockDiagnostician {
	d := &mockDiagnostician{errorRateThreshold: 10, rttSpikeThreshold: 100}
	for i := 0; i < 10; i++ {
		d.events = append(d.events, &events.Event{Type: events.EventConnect, Error: 111})
	}
	return d
}

func TestASessionNoIssueStartedHasNoTriggerSection(t *testing.T) {
	if got := GenerateTriggerSection(Trigger{}, failingConnects()); got != "" {
		t.Errorf("section = %q", got)
	}
}

func TestTheTriggerSectionNamesTheIssueAndWhereToLook(t *testing.T) {
	got := GenerateTriggerSection(Trigger{
		IssueID:  string(detector.IDL7ErrorRate),
		Severity: "warning",
		Pod:      "shop/api-0",
		At:       "2026-10-02T09:14:03Z",
		Reason:   "High application error rate for shop/api: 100.0%",
	}, failingConnects())
	for _, want := range []string{
		"=== Started by issue l7.error_rate ===",
		"Severity:       warning",
		"Pod:            shop/api-0",
		"Fired at:       2026-10-02T09:14:03Z",
		"Agent measured: High application error rate for shop/api: 100.0%",
		"does not raise this issue itself",
		"Look first at:  HTTP Statistics",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("section lacks %q:\n%s", want, got)
		}
	}
}

func TestTheTriggerSectionSaysWhenTheSessionSawTheIssueToo(t *testing.T) {
	got := GenerateTriggerSection(Trigger{IssueID: string(detector.IDConnectionFailureRate)}, failingConnects())
	if !strings.Contains(got, "detected it too") {
		t.Errorf("section does not say the session saw it:\n%s", got)
	}
}

func TestTheTriggerSectionSaysWhenTheIssueHadClearedBeforeTheSession(t *testing.T) {
	got := GenerateTriggerSection(Trigger{IssueID: string(detector.IDConnectionFailureRate)}, &mockDiagnostician{errorRateThreshold: 10})
	if !strings.Contains(got, "did not detect it") {
		t.Errorf("section does not say the session missed it:\n%s", got)
	}
}

func TestTheTriggerSectionStripsTerminalControlFromTheReason(t *testing.T) {
	got := GenerateTriggerSection(Trigger{IssueID: string(detector.IDCPUContention), Reason: "slow\x1b[2Jcleared"}, nil)
	if strings.Contains(got, "\x1b") {
		t.Errorf("an escape sequence reached the report: %q", got)
	}
	if !strings.Contains(got, "Look first at:  CPU Statistics") {
		t.Errorf("section lacks the CPU pointer:\n%s", got)
	}
}

func TestEveryIssueHasASectionToLookAt(t *testing.T) {
	for _, id := range detector.Registry {
		if _, ok := issueSections[id]; !ok {
			t.Errorf("%s has no report section to point at", id)
		}
	}
}

func TestTheReportRedactorLeavesTheTriggerSectionIntact(t *testing.T) {
	trigger := Trigger{
		IssueID:  string(detector.IDConnectionFailureRate),
		Severity: "warning",
		Pod:      "shop/api-0",
		At:       "2026-10-02T09:14:03Z",
		Reason:   "High connection failure rate for shop/api: 90.0% (9/10)",
	}
	for name, d := range map[string]*mockDiagnostician{
		"detected":     failingConnects(),
		"not detected": {errorRateThreshold: 10},
	} {
		section := GenerateTriggerSection(trigger, d)
		if got := redactor.Default().RedactText(section); got != section {
			t.Errorf("%s: the redactor rewrote the section:\n%s\nwant:\n%s", name, got, section)
		}
	}
	section := GenerateTriggerSection(Trigger{IssueID: string(detector.IDL7ErrorRate)}, nil)
	if got := redactor.Default().RedactText(section); got != section {
		t.Errorf("the redactor rewrote the section:\n%s\nwant:\n%s", got, section)
	}
}
