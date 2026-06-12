package redactor

import (
	"os"
	"regexp"

	"github.com/podtrace/podtrace/internal/events"
)

// Rule describes one PII redaction pattern applied to event string fields.
type Rule struct {
	Name    string
	Pattern *regexp.Regexp
	Replace string
}

// Redactor applies a list of Rules to event Target and Details fields in-place.
type Redactor struct {
	rules          []Rule
	redactDNSNames bool
}

// Default returns a Redactor with built-in rules for common PII patterns.
func Default() *Redactor {
	return &Redactor{
		rules:          defaultRules(),
		redactDNSNames: os.Getenv("PODTRACE_REDACT_DNS_NAMES") == "true",
	}
}

// New creates a Redactor with the provided rules.
func New(rules []Rule) *Redactor {
	return &Redactor{rules: rules}
}

// Redact modifies e.Target and e.Details in-place, applying all rules.
func (r *Redactor) Redact(e *events.Event) {
	if e == nil {
		return
	}
	if r.redactDNSNames {
		switch e.Type {
		case events.EventDNS, events.EventDNSQuery:
			e.Target = "[redacted]"
		case events.EventConnect:
			if e.Details != "" {
				e.Details = "[redacted]"
			}
		}
	}
	for _, rule := range r.rules {
		e.Target = rule.Pattern.ReplaceAllString(e.Target, rule.Replace)
		e.Details = rule.Pattern.ReplaceAllString(e.Details, rule.Replace)
	}
}

func defaultRules() []Rule {
	return []Rule{
		{
			Name:    "credential_kv",
			Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd|token|api[_-]?key|apikey|secret|access[_-]?key|auth)=[^\s&]+`),
			Replace: "${1}=***",
		},
		{
			Name:    "bearer_token",
			Pattern: regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/\-]+=*`),
			Replace: "Bearer ***",
		},
		{
			Name:    "basic_auth",
			Pattern: regexp.MustCompile(`(?i)Basic\s+[A-Za-z0-9+/]+=*`),
			Replace: "Basic ***",
		},
		{
			Name:    "credential_json",
			Pattern: regexp.MustCompile(`(?i)"(password|passwd|pwd|token|api[_-]?key|apikey|secret|access[_-]?key)"\s*:\s*"[^"]*"`),
			Replace: `"${1}":"***"`,
		},
		{
			Name:    "credential_yaml",
			Pattern: regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|secret|access[_-]?key)\s*:\s+[^\s,}]+`),
			Replace: "${1}: ***",
		},
		{
			Name:    "email",
			Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			Replace: "***@***",
		},
		{
			Name:    "credit_card",
			Pattern: regexp.MustCompile(`\b(\d{4}[\s\-]?){3}\d{4}\b`),
			Replace: "****-****-****-****",
		},
	}
}
