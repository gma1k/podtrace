package redactor

import (
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

// TestDefaultRules_CredentialForms: the default rule set only caught
// password= query params and Bearer tokens — token=, api_key=, secret=,
// Basic auth, and JSON/YAML password bodies all passed through unredacted.
func TestDefaultRules_CredentialForms(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		leaked   string
		survives string
	}{
		{"token query", "GET /cb?token=sk_live_4242&x=1", "sk_live_4242", "/cb"},
		{"api_key query", "POST /v1?api_key=AKIAEXAMPLE", "AKIAEXAMPLE", "/v1"},
		{"apikey query", "GET /v1?apikey=abc123def", "abc123def", "/v1"},
		{"secret query", "GET /auth?secret=s3cr3t", "s3cr3t", "/auth"},
		{"access_key query", "PUT /b?access_key=AK99", "AK99", "/b"},
		{"basic auth", "Authorization: Basic dXNlcjpodW50ZXIy", "dXNlcjpodW50ZXIy", "Authorization"},
		{"json password", `{"user":"bob","password":"hunter2"}`, "hunter2", "bob"},
		{"json api_key", `{"api_key": "AKIA123", "region":"eu"}`, "AKIA123", "eu"},
		{"yaml password", "password: hunter2", "hunter2", "password"},
		{"yaml token", "token: ghp_abcdef123", "ghp_abcdef123", "token"},
	}

	r := Default()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &events.Event{Type: events.EventHTTPReq, Target: c.in, Details: c.in}
			r.Redact(e)
			for field, v := range map[string]string{"Target": e.Target, "Details": e.Details} {
				if strings.Contains(v, c.leaked) {
					t.Errorf("%s still leaks %q: %q", field, c.leaked, v)
				}
				if c.survives != "" && !strings.Contains(v, c.survives) {
					t.Errorf("%s lost non-secret context %q: %q", field, c.survives, v)
				}
			}
		})
	}
}
