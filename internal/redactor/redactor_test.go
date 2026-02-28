package redactor_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/redactor"
)

func makeEvent(target, details string) *events.Event {
	return &events.Event{Target: target, Details: details}
}

func TestRedact_Password(t *testing.T) {
	r := redactor.Default()
	e := makeEvent("", "password=secret123&foo=bar")
	r.Redact(e)
	if strings.Contains(e.Details, "secret123") {
		t.Errorf("password not redacted: %q", e.Details)
	}
	if !strings.Contains(e.Details, "password=***") {
		t.Errorf("expected password=***: %q", e.Details)
	}
}

func TestRedact_BearerToken(t *testing.T) {
	r := redactor.Default()
	e := makeEvent("", "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload")
	r.Redact(e)
	if strings.Contains(e.Details, "eyJ") {
		t.Errorf("bearer token not redacted: %q", e.Details)
	}
	if !strings.Contains(e.Details, "Bearer ***") {
		t.Errorf("expected Bearer ***: %q", e.Details)
	}
}

func TestRedact_Email(t *testing.T) {
	r := redactor.Default()
	e := makeEvent("user@example.com", "contact: admin@test.org")
	r.Redact(e)
	if strings.Contains(e.Target, "@example.com") {
		t.Errorf("email in target not redacted: %q", e.Target)
	}
	if strings.Contains(e.Details, "@test.org") {
		t.Errorf("email in details not redacted: %q", e.Details)
	}
}

func TestRedact_CreditCard(t *testing.T) {
	r := redactor.Default()
	e := makeEvent("", "card: 4111 1111 1111 1111 charged")
	r.Redact(e)
	if strings.Contains(e.Details, "4111") {
		t.Errorf("credit card not redacted: %q", e.Details)
	}
}

func TestRedact_NilEvent(t *testing.T) {
	r := redactor.Default()
	r.Redact(nil) // must not panic
}

func TestRedact_NoMatchIsIdempotent(t *testing.T) {
	r := redactor.Default()
	e := makeEvent("192.168.1.1:8080", "GET /health")
	r.Redact(e)
	if e.Target != "192.168.1.1:8080" {
		t.Errorf("target unexpectedly modified: %q", e.Target)
	}
	if e.Details != "GET /health" {
		t.Errorf("details unexpectedly modified: %q", e.Details)
	}
}

func TestNew_CustomRule(t *testing.T) {
	rules := []redactor.Rule{
		{
			Name:    "ssn",
			Pattern: regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			Replace: "***-**-****",
		},
	}
	r := redactor.New(rules)
	e := makeEvent("", "ssn: 123-45-6789")
	r.Redact(e)
	if strings.Contains(e.Details, "123-45-6789") {
		t.Errorf("SSN not redacted: %q", e.Details)
	}
	if !strings.Contains(e.Details, "***-**-****") {
		t.Errorf("expected redacted SSN: %q", e.Details)
	}
}
