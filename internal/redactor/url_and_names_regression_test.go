package redactor

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func redactBoth(t *testing.T, r *Redactor, in, leaked, keep string) {
	t.Helper()
	e := &events.Event{Type: events.EventHTTPReq, Target: in, Details: in}
	r.Redact(e)
	for _, v := range []string{e.Target, e.Details} {
		if leaked != "" && strings.Contains(v, leaked) {
			t.Errorf("leaked %q in %q (input %q)", leaked, v, in)
		}
		if keep != "" && !strings.Contains(v, keep) {
			t.Errorf("lost context %q in %q (input %q)", keep, v, in)
		}
	}
}

func TestDefaultRules_URLUserinfoRedacted(t *testing.T) {
	r := Default()
	cases := []struct{ in, leaked, keep string }{
		{"GET http://admin:s3cr3t@host/path", "s3cr3t", "host"},
		{"conn redis://user:redispw@redis.svc/0", "redispw", "redis.svc"},
		{"postgres://u:pgpw@db:5432/app", "pgpw", "db:5432"},
		{"login https://root:toor@10.0.0.5/", "toor", "10.0.0.5"},
		{"user only http://tokenuser@api/", "tokenuser", "api"},
	}
	for _, c := range cases {
		redactBoth(t, r, c.in, c.leaked, c.keep)
	}
}

func TestDefaultRules_AdditionalCredentialKeys(t *testing.T) {
	r := Default()
	cases := []struct{ in, leaked, keep string }{
		{"GET /k?private_key=MIIEpriv", "MIIEpriv", "/k"},
		{"GET /k?private-key=MIIEpriv2", "MIIEpriv2", "/k"},
		{"POST /c?client_key=ck_live_9", "ck_live_9", "/c"},
		{"GET /p?passphrase=letmein", "letmein", "/p"},
		{"GET /s?signature=SIGZ9", "SIGZ9", "/s"},
		{"GET /x?credential=cred77", "cred77", "/x"},
		{`{"private_key":"PEMDATA"}`, "PEMDATA", ""},
		{"passphrase: letmein2", "letmein2", "passphrase"},
	}
	for _, c := range cases {
		redactBoth(t, r, c.in, c.leaked, c.keep)
	}
}

func TestDefaultRules_AuthenticateHeaders(t *testing.T) {
	r := Default()
	cases := []struct{ in, leaked, keep string }{
		{`WWW-Authenticate: Bearer realm="x", error="invalid_token"`, "invalid_token", "WWW-Authenticate"},
		{`Proxy-Authenticate: Basic realm="proxy-realm-secret"`, "proxy-realm-secret", "Proxy-Authenticate"},
	}
	for _, c := range cases {
		redactBoth(t, r, c.in, c.leaked, c.keep)
	}
}
