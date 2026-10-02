package operator

import (
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func issueEvent(id, message string) *corev1.Event {
	at := time.Date(2026, 10, 2, 9, 14, 3, 0, time.UTC)
	return alerting.BuildAlertEvent(&alerting.Alert{
		Severity:  alerting.SeverityWarning,
		Source:    alerting.AlertSourceIssue,
		ErrorCode: id,
		Title:     message,
		PodName:   "api-0",
		Namespace: "shop",
	}, at)
}

func TestAnIssueEventCarriesItsIssueAndReason(t *testing.T) {
	ev, ok := parseAlertEvent(issueEvent(string(detector.IDL7ErrorRate), "  High application error rate for shop/api  "))
	if !ok {
		t.Fatal("an issue Event was not parsed")
	}
	if ev.IssueID != string(detector.IDL7ErrorRate) {
		t.Errorf("IssueID = %q, want %q", ev.IssueID, detector.IDL7ErrorRate)
	}
	if ev.Reason != "High application error rate for shop/api" {
		t.Errorf("Reason = %q", ev.Reason)
	}
}

func TestAnIssueEventWithAnUnknownIDCarriesNoIssue(t *testing.T) {
	ev, ok := parseAlertEvent(issueEvent("made.up", "x"))
	if !ok {
		t.Fatal("an issue Event was not parsed")
	}
	if ev.IssueID != "" {
		t.Errorf("IssueID = %q; an id outside the registry must not reach a session", ev.IssueID)
	}
}

func TestANonIssueEventIgnoresAnIssueAnnotation(t *testing.T) {
	raw := issueEvent(string(detector.IDL7ErrorRate), "oom")
	raw.Annotations[alerting.AnnotationAlertSource] = alerting.AlertSourceOOM
	ev, ok := parseAlertEvent(raw)
	if !ok {
		t.Fatal("an OOM Event was not parsed")
	}
	if ev.IssueID != "" || ev.Reason != "" {
		t.Errorf("OOM Event carried issue %q, reason %q", ev.IssueID, ev.Reason)
	}
}

func TestATriggerReasonIsBoundedOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("a", maxTriggerReasonBytes-1) + "é" + "tail"
	got := truncateReason(long)
	if len(got) > maxTriggerReasonBytes {
		t.Errorf("len = %d, want at most %d", len(got), maxTriggerReasonBytes)
	}
	if !utf8.ValidString(got) {
		t.Error("truncation split a multi-byte rune")
	}
	if got != strings.Repeat("a", maxTriggerReasonBytes-1) {
		t.Errorf("truncated to %d bytes, want the run of a's before the rune", len(got))
	}
}

func TestAnIssueSourceWithAnIDMatchesOnlyThatIssue(t *testing.T) {
	sources := []podtracev1alpha1.TriggerSource{{
		Kind:        podtracev1alpha1.TriggerSourceIssue,
		MinSeverity: "warning",
		IssueID:     string(detector.IDL7ErrorRate),
	}}
	errorRate := alertEvent{Kind: podtracev1alpha1.TriggerSourceIssue, Severity: "warning", IssueID: string(detector.IDL7ErrorRate)}
	contention := alertEvent{Kind: podtracev1alpha1.TriggerSourceIssue, Severity: "critical", IssueID: string(detector.IDCPUContention)}
	if !matchesTriggerSources(errorRate, sources) {
		t.Error("the selected issue did not match")
	}
	if matchesTriggerSources(contention, sources) {
		t.Error("another issue matched a source that names l7.error_rate")
	}
}

func TestAnIssueSourceWithoutAnIDMatchesEveryIssue(t *testing.T) {
	sources := []podtracev1alpha1.TriggerSource{{Kind: podtracev1alpha1.TriggerSourceIssue, MinSeverity: "warning"}}
	for _, id := range detector.Registry {
		ev := alertEvent{Kind: podtracev1alpha1.TriggerSourceIssue, Severity: "warning", IssueID: string(id)}
		if !matchesTriggerSources(ev, sources) {
			t.Errorf("%s did not match an Issue source with no issueID", id)
		}
	}
}

func TestASessionNoIssueStartedGetsNoTriggerArgs(t *testing.T) {
	if args := triggerIssueArgs(nil); args != nil {
		t.Errorf("args = %v", args)
	}
	if args := triggerIssueArgs(map[string]string{alerting.AnnotationIssueID: "made.up"}); args != nil {
		t.Errorf("an unknown issue id produced args %v", args)
	}
}

func TestATriggeredSessionPassesItsIssueToTheJob(t *testing.T) {
	s := minimalSession()
	s.Annotations = map[string]string{
		alerting.AnnotationIssueID: string(detector.IDL7ErrorRate),
		AnnotationTriggerSeverity:  "warning",
		AnnotationTriggerPod:       "shop/api-0",
		AnnotationTriggeredAt:      "2026-10-02T09:14:03Z",
		AnnotationTriggerReason:    "High application error rate",
	}
	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"}}
	args := buildSessionJobSpec(s, tc, "node-a", sessionTargets{}).Template.Spec.Containers[0].Args
	for _, pair := range [][2]string{
		{"--trigger-issue", string(detector.IDL7ErrorRate)},
		{"--trigger-severity", "warning"},
		{"--trigger-pod", "shop/api-0"},
		{"--trigger-at", "2026-10-02T09:14:03Z"},
		{"--trigger-reason", "High application error rate"},
	} {
		i := slices.Index(args, pair[0])
		if i < 0 || i+1 >= len(args) || args[i+1] != pair[1] {
			t.Errorf("args lack %s %q: %v", pair[0], pair[1], args)
		}
	}
}

func TestTheCRDIssueIDEnumIsTheIssueRegistry(t *testing.T) {
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	var plain []string
	for _, line := range strings.Split(repoFile(t, "deploy", "charts", "podtrace", "templates", "crds", "podtrace.io_podtraceschedules.yaml"), "\n") {
		if !strings.Contains(line, "{{") {
			plain = append(plain, line)
		}
	}
	if err := yaml.Unmarshal([]byte(strings.Join(plain, "\n")), &crd); err != nil {
		t.Fatalf("parse CRD: %v", err)
	}
	node := any(crd.Spec.Versions[0].Schema.OpenAPIV3Schema)
	for _, key := range []string{"properties", "spec", "properties", "trigger", "properties", "sources", "items", "properties", "issueID", "enum"} {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("CRD schema has no %q", key)
		}
		node = m[key]
	}
	list, _ := node.([]any)
	var got []string
	for _, v := range list {
		got = append(got, v.(string))
	}
	var want []string
	for _, id := range detector.Registry {
		want = append(want, string(id))
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("CRD issueID enum = %v, registry = %v; a schedule could not select an issue the agent raises, or could select one it never will", got, want)
	}
}
