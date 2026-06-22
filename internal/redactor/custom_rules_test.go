package redactor_test

import (
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/redactor"
)

func TestDefaultWithCustomRules_Empty(t *testing.T) {
	r, err := redactor.DefaultWithCustomRules("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := makeEvent("", "password=hunter2")
	r.Redact(e)
	if strings.Contains(e.Details, "hunter2") {
		t.Errorf("built-in rule did not apply: %q", e.Details)
	}
}

func TestDefaultWithCustomRules_AppliesCustomAndBuiltin(t *testing.T) {
	spec := `[{"name":"ssn","pattern":"\\d{3}-\\d{2}-\\d{4}","replace":"***-**-****"}]`
	r, err := redactor.DefaultWithCustomRules(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e := makeEvent("ssn 123-45-6789", "password=hunter2")
	r.Redact(e)
	if strings.Contains(e.Target, "123-45-6789") {
		t.Errorf("custom SSN rule not applied: %q", e.Target)
	}
	if strings.Contains(e.Details, "hunter2") {
		t.Errorf("built-in rule not applied alongside custom: %q", e.Details)
	}
}

func TestDefaultWithCustomRules_InvalidRegexIsFailSafe(t *testing.T) {
	spec := `[{"name":"bad","pattern":"[","replace":"x"},{"name":"ok","pattern":"secret-\\d+","replace":"***"}]`
	r, err := redactor.DefaultWithCustomRules(spec)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
	e := makeEvent("secret-42", "password=hunter2")
	r.Redact(e)
	if strings.Contains(e.Target, "secret-42") {
		t.Errorf("valid custom rule should still apply: %q", e.Target)
	}
	if strings.Contains(e.Details, "hunter2") {
		t.Errorf("built-in rule should survive bad custom rule: %q", e.Details)
	}
}

func TestParseRules_MalformedJSON(t *testing.T) {
	if _, err := redactor.ParseRules("not json"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
