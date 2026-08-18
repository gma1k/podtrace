package main

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestRedactReportText_ScrubsSecretsBeforeSink(t *testing.T) {
	report := strings.Join([]string{
		"=== Diagnostic Report ===",
		"Top URLs:",
		"  - /login?token=SUPERSECRET",
		"Captured headers:",
		"  Cookie: sid=deadbeef",
		"  Authorization: Bearer AAA.BBB.CCC",
	}, "\n")

	got := redactReportText(report)

	for _, leak := range []string{"SUPERSECRET", "deadbeef", "AAA.BBB.CCC"} {
		if strings.Contains(got, leak) {
			t.Errorf("report reached the sink with %q unredacted:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "Diagnostic Report") {
		t.Errorf("redaction destroyed report structure:\n%s", got)
	}
}

func TestRedactReportText_InvalidCustomRulesStillRedactsWithDefaults(t *testing.T) {
	orig := config.RedactCustomRules
	config.RedactCustomRules = `[{"name":"bad","pattern":"([","replace":"x"}]`
	defer func() { config.RedactCustomRules = orig }()

	got := redactReportText("Cookie: sid=deadbeef")
	if strings.Contains(got, "deadbeef") {
		t.Errorf("invalid custom rules must fall back to default redaction, got %q", got)
	}
}
