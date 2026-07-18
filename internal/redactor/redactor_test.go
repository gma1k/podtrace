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
	e := makeEvent("", "grpc call carried Bearer eyJhbGciOiJSUzI1NiJ9.payload downstream")
	r.Redact(e)
	if strings.Contains(e.Details, "eyJ") {
		t.Errorf("bearer token not redacted: %q", e.Details)
	}
	if !strings.Contains(e.Details, "Bearer ***") {
		t.Errorf("expected Bearer ***: %q", e.Details)
	}
}

func TestRedact_AuthorizationHeaderFullyRedacted(t *testing.T) {
	r := redactor.Default()
	e := makeEvent("", "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload")
	r.Redact(e)
	if strings.Contains(e.Details, "eyJ") {
		t.Errorf("authorization token not redacted: %q", e.Details)
	}
	if !strings.Contains(e.Details, "Authorization: ***") {
		t.Errorf("expected the whole Authorization value redacted: %q", e.Details)
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

func TestRedact_DNSNames_Toggle(t *testing.T) {
	dnsEvent := func() *events.Event {
		return &events.Event{Type: events.EventDNS, Target: "secret-internal.example.com"}
	}

	// Default (env unset): DNS names are kept.
	t.Setenv("PODTRACE_REDACT_DNS_NAMES", "")
	e := dnsEvent()
	redactor.Default().Redact(e)
	if e.Target != "secret-internal.example.com" {
		t.Errorf("name should be kept by default, got %q", e.Target)
	}

	// Opt-in: DNS names are redacted.
	t.Setenv("PODTRACE_REDACT_DNS_NAMES", "true")
	e = dnsEvent()
	redactor.Default().Redact(e)
	if e.Target != "[redacted]" {
		t.Errorf("name should be redacted, got %q", e.Target)
	}

	// Redaction must not touch non-DNS events.
	t.Setenv("PODTRACE_REDACT_DNS_NAMES", "true")
	c := &events.Event{Type: events.EventConnect, Target: "1.2.3.4:443"}
	redactor.Default().Redact(c)
	if c.Target != "1.2.3.4:443" {
		t.Errorf("connect target should be untouched, got %q", c.Target)
	}
}

// TestRedact_DNSNameBypasses is a regression test for the redaction
// bypasses: EventDNSQuery (which also carries a query name in Target) and
// the DNS-correlated hostname in EventConnect.Details were exempt from
// PODTRACE_REDACT_DNS_NAMES.
func TestRedact_DNSNameBypasses(t *testing.T) {
	t.Setenv("PODTRACE_REDACT_DNS_NAMES", "true")
	r := redactor.Default()

	query := &events.Event{Type: events.EventDNSQuery, Target: "secret-host.internal"}
	r.Redact(query)
	if query.Target != "[redacted]" {
		t.Errorf("EventDNSQuery target = %q, want [redacted]", query.Target)
	}

	connect := &events.Event{Type: events.EventConnect, Target: "10.0.0.8:00443", Details: "secret-host.internal"}
	r.Redact(connect)
	if connect.Details != "[redacted]" {
		t.Errorf("EventConnect details = %q, want [redacted]", connect.Details)
	}
	if connect.Target != "10.0.0.8:00443" {
		t.Errorf("EventConnect target must keep the ip:port, got %q", connect.Target)
	}

	answer := &events.Event{Type: events.EventDNS, Target: "secret-internal.example.com", Details: "192.0.2.7"}
	r.Redact(answer)
	if answer.Details != "[redacted]" {
		t.Errorf("EventDNS answer IP left in Details = %q, want [redacted]", answer.Details)
	}
}
