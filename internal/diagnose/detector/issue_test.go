package detector

import (
	"sort"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/events"
)

func TestTheIssueVocabularyIsStable(t *testing.T) {
	want := []string{
		"net.connection_failure_rate",
		"net.rtt_spike_rate",
		"resource.saturation",
		"l7.error_rate",
		"l7.latency_degraded",
		"db.connection_acquire_slow",
		"db.pool_saturated",
		"cpu.contention",
	}

	got := make([]string, 0, len(Registry))
	for _, id := range Registry {
		got = append(got, string(id))
	}
	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("registry has %d ids, snapshot has %d: %v vs %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("id %d is %q, snapshot says %q.\n\nIssue ids appear in "+
				"podtrace_issue_active{id=...} and in alert routing, so they are contractual: "+
				"adding one is a minor and updating this snapshot is expected, but renaming one "+
				"breaks every alert rule built on it.", i, got[i], want[i])
		}
	}
}

func TestEveryRegisteredIDIsNamespaced(t *testing.T) {
	for _, id := range Registry {
		domain, rest, found := strings.Cut(string(id), ".")
		if !found || domain == "" || rest == "" {
			t.Errorf("id %q is not domain-qualified; the vocabulary stays legible as it grows "+
				"only if every id names its domain", id)
		}
		if strings.ToLower(string(id)) != string(id) {
			t.Errorf("id %q is not lowercase; a label value that varies by case is two series", id)
		}
	}
}

func TestRegistryHasNoDuplicates(t *testing.T) {
	seen := map[ID]bool{}
	for _, id := range Registry {
		if seen[id] {
			t.Errorf("id %q appears twice in the registry", id)
		}
		seen[id] = true
	}
}

func TestEveryEmittedIssueIsRegisteredAndComplete(t *testing.T) {
	registered := map[ID]bool{}
	for _, id := range Registry {
		registered[id] = true
	}

	evs := []*events.Event{
		{Type: events.EventConnect, Error: 1},
		{Type: events.EventConnect, Error: 1},
		{Type: events.EventTCPSend, LatencyNS: 900_000_000},
		{Type: events.EventTCPSend, LatencyNS: 900_000_000},
		{Type: events.EventResourceLimit, Error: 99, TCPState: 0},
	}

	issues := DetectIssues(evs, 10, 1)
	if len(issues) == 0 {
		t.Fatal("no issues detected from a batch designed to trip every rule")
	}

	for _, issue := range issues {
		if !registered[issue.ID] {
			t.Errorf("issue %q is emitted but not in Registry; an unregistered id is "+
				"undocumented and cannot be alerted on deliberately", issue.ID)
		}
		if issue.Severity == "" {
			t.Errorf("issue %q has no severity; the operator's trigger machinery ranks "+
				"severities and an empty one ranks as unknown", issue.ID)
		}
		if issue.Message == "" {
			t.Errorf("issue %q has no message; the report renders this", issue.ID)
		}
		if issue.Remediation == "" {
			t.Errorf("issue %q has no remediation; an issue that cannot say what to do next "+
				"is a notification, not a diagnosis", issue.ID)
		}
		if len(issue.Evidence) == 0 {
			t.Errorf("issue %q carries no evidence; without the measured value a consumer "+
				"has to re-derive why it fired", issue.ID)
		}
	}
}

func TestSeverityUsesTheProductsOneVocabulary(t *testing.T) {
	valid := map[alerting.AlertSeverity]bool{
		alerting.SeverityFatal:    true,
		alerting.SeverityCritical: true,
		alerting.SeverityWarning:  true,
		alerting.SeverityError:    true,
	}
	evs := []*events.Event{{Type: events.EventResourceLimit, Error: 99, TCPState: 1}}
	for _, issue := range DetectIssues(evs, 10, 1) {
		if !valid[issue.Severity] {
			t.Errorf("issue %q has severity %q, which is outside alerting.AlertSeverity; a "+
				"parallel vocabulary ranks as unknown in the trigger machinery",
				issue.ID, issue.Severity)
		}
	}
}

func TestSeverityForUtilizationRanksByBand(t *testing.T) {
	for _, tc := range []struct {
		pct  int
		want alerting.AlertSeverity
		fire bool
	}{
		{10, "", false},
		{75, alerting.SeverityWarning, true},
		{90, alerting.SeverityCritical, true},
		{99, alerting.SeverityFatal, true},
	} {
		got, firing := severityForUtilization(tc.pct, 70, 85, 95)
		if firing != tc.fire || got != tc.want {
			t.Errorf("severityForUtilization(%d) = %q,%v; want %q,%v",
				tc.pct, got, firing, tc.want, tc.fire)
		}
	}
}

func TestIssueKeyIdentifiesAnInstanceForDeduplication(t *testing.T) {
	a := Issue{ID: IDResourceSaturation, Subject: Subject{Workload: "web", Resource: "CPU"}}
	b := Issue{ID: IDResourceSaturation, Subject: Subject{Workload: "web", Resource: "CPU"}}
	c := Issue{ID: IDResourceSaturation, Subject: Subject{Workload: "web", Resource: "Memory"}}

	if a.Key() != b.Key() {
		t.Error("the same rule firing for the same subject must be one issue, or every " +
			"evaluation raises a fresh alert")
	}
	if a.Key() == c.Key() {
		t.Error("different resources are different issues; collapsing them hides one of them")
	}
}

func TestStringsRendersForTextConsumers(t *testing.T) {
	issues := []Issue{{Message: "first"}, {Message: "second"}}
	got := Strings(issues)
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("Strings = %v, want the messages in order", got)
	}
	if got := Strings(nil); len(got) != 0 {
		t.Errorf("Strings(nil) = %v, want empty", got)
	}
}

func TestIssueStringsAsItsMessage(t *testing.T) {
	i := Issue{ID: IDRTTSpikeRate, Message: "High TCP RTT spike rate: 50.0%"}
	if got := i.String(); got != i.Message {
		t.Errorf("String() = %q, want the message; the report prints issues directly and "+
			"changing this changes report output", got)
	}
}

func TestResourceIssuesIgnoreNonPhysicalAndUnknownKinds(t *testing.T) {
	evs := []*events.Event{

		{Type: events.EventResourceLimit, Error: -5, TCPState: 0},

		{Type: events.EventResourceLimit, Error: 99, TCPState: 77},
	}

	issues := DetectIssues(evs, 10, 1)
	for _, issue := range issues {
		for _, ev := range issue.Evidence {
			if ev.Name == "utilization" && ev.Value < 0 {
				t.Errorf("a negative utilization became an issue: %+v", issue)
			}
		}
	}

	var generic bool
	for _, issue := range issues {
		if issue.Subject.Resource == "Resource" {
			generic = true
		}
	}
	if !generic {
		t.Error("an unknown resource kind was dropped; a new kind added on the BPF side " +
			"would go unreported rather than reported generically")
	}
}

func TestTheExportedHelpersMatchTheirInternalForms(t *testing.T) {

	for _, pct := range []int{0, 10, 70, 80, 85, 90, 95, 99, 100, 150} {
		wantSev, wantFiring := severityForUtilization(pct, 80, 90, 95)
		gotSev, gotFiring := SeverityForUtilization(pct, 80, 90, 95)
		if gotSev != wantSev || gotFiring != wantFiring {
			t.Errorf("SeverityForUtilization(%d) = %q,%v; internal form says %q,%v",
				pct, gotSev, gotFiring, wantSev, wantFiring)
		}
	}

	for _, sev := range []alerting.AlertSeverity{
		alerting.SeverityFatal, alerting.SeverityCritical,
		alerting.SeverityWarning, alerting.SeverityError,
		alerting.AlertSeverity("unknown"),
	} {
		if got, want := SeverityLabel(sev), severityLabel(sev); got != want {
			t.Errorf("SeverityLabel(%q) = %q, internal form says %q", sev, got, want)
		}
	}

	got := NewEvidence("utilization", 93, 80, "%")
	want := evidence("utilization", 93, 80, "%")
	if got != want {
		t.Errorf("NewEvidence = %+v, internal form = %+v", got, want)
	}
}
