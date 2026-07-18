package redactor

import (
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestDefaultRules_SessionAndAuthHeaders(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		leaked   []string
		survives string
	}{
		{
			name:     "cookie header jar",
			in:       "cookie: session=abc123; JSESSIONID=deadbeef; sid=99",
			leaked:   []string{"abc123", "deadbeef", "99"},
			survives: "cookie",
		},
		{
			name:     "set-cookie header",
			in:       "set-cookie: sid=s3cr3t; Path=/; HttpOnly",
			leaked:   []string{"s3cr3t"},
			survives: "set-cookie",
		},
		{
			name:     "opaque authorization header",
			in:       "authorization: opaque-token-xyz",
			leaked:   []string{"opaque-token-xyz"},
			survives: "authorization",
		},
		{
			name:     "bearer authorization header",
			in:       "authorization: Bearer aGVsbG8xMjM0NTY",
			leaked:   []string{"aGVsbG8xMjM0NTY"},
			survives: "authorization",
		},
		{
			name:     "authorization equals form",
			in:       "GET /cb?authorization=mytoken&next=/home",
			leaked:   []string{"mytoken"},
			survives: "/home",
		},
		{
			name:     "sessionid query param",
			in:       "GET /login?sessionid=leakme&theme=dark",
			leaked:   []string{"leakme"},
			survives: "theme=dark",
		},
		{
			name:     "session in body stops at semicolon",
			in:       "body: session=abc;keepme=1",
			leaked:   []string{"abc"},
			survives: "keepme=1",
		},
	}

	r := Default()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &events.Event{Type: events.EventHTTPReq, Target: c.in, Details: c.in}
			r.Redact(e)
			for field, v := range map[string]string{"Target": e.Target, "Details": e.Details} {
				for _, leak := range c.leaked {
					if strings.Contains(v, leak) {
						t.Errorf("%s still leaks %q: %q", field, leak, v)
					}
				}
				if c.survives != "" && !strings.Contains(v, c.survives) {
					t.Errorf("%s lost non-secret context %q: %q", field, c.survives, v)
				}
			}
		})
	}
}

func TestDefaultRules_TraceStateRedacted(t *testing.T) {
	e := &events.Event{
		Type:       events.EventHTTPReq,
		TraceState: "vendorA=ok,token=supersecret,vendorB=fine",
	}
	Default().Redact(e)
	if strings.Contains(e.TraceState, "supersecret") {
		t.Errorf("TraceState still leaks the token: %q", e.TraceState)
	}
	if !strings.Contains(e.TraceState, "vendorA=ok") || !strings.Contains(e.TraceState, "vendorB=fine") {
		t.Errorf("TraceState lost non-secret vendor entries: %q", e.TraceState)
	}
}
