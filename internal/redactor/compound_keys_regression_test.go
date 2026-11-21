package redactor

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestDefaultRules_CompoundCredentialKeys(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		survives string
	}{
		{"json snake prefix", `{"db_password":"hunter2"}`, `"db_password":"***"`},
		{"json snake suffix", `{"client_secret":"hunter2"}`, `"client_secret":"***"`},
		{"json camel", `{"accessToken":"hunter2"}`, `"accessToken":"***"`},
		{"json camel prefix", `{"newPassword":"hunter2"}`, `"newPassword":"***"`},
		{"json kebab pair", `{"x-api-key":"hunter2"}`, `"x-api-key":"***"`},
		{"json aws secret", `{"aws_secret_access_key":"hunter2"}`, `"aws_secret_access_key":"***"`},
		{"json acronym pair", `{"APIKey":"hunter2"}`, `"APIKey":"***"`},
		{"json session id pair", `{"sessionId":"hunter2"}`, `"sessionId":"***"`},
		{"json number value", `{"pinPasscode": 4242424}`, `"pinPasscode":"***"`},
		{"json array value", `{"password":["hunter2","x"],"user":"bob"}`, `"password":"***","user":"bob"`},
		{"json object value", `{"password":{"value":"hunter2"},"user":"bob"}`, `"password":"***","user":"bob"`},
		{"json nested object value", `{"token":{"a":[1,"}"],"b":{"c":"hunter2"}}, "user":"bob"}`, `"token":"***", "user":"bob"`},
		{"json truncated array", `{"secret":["hunter2", "x`, `"secret":"***"`},
		{"json truncated string", `{"db_password":"hunt`, `"db_password":"***"`},
		{"escaped json compound", `"{\"db_password\":\"hunter2\"}"`, `\"db_password\":\"***\"`},
		{"yaml snake", "db_password: hunter2", "db_password: ***"},
		{"yaml camel", "dbPassword: hunter2", "dbPassword: ***"},
		{"xml element", `<password>hunter2</password>`, `<password>***</password>`},
		{"xml prefixed compound", `<ns:dbPassword a="1">hunter2</ns:dbPassword>`, `<ns:dbPassword a="1">***</ns:dbPassword>`},
		{"long flag", `app --password hunter2 -v`, `--password *** -v`},
		{"compound flag quoted", `app --db-password "hunter 2" -v`, `--db-password *** -v`},
		{"single dash flag", `app -token hunter2`, `-token ***`},
	}
	r := Default()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.RedactText(c.in)
			if strings.Contains(got, "hunter") {
				t.Errorf("still leaks: %q", got)
			}
			if !strings.Contains(got, c.survives) {
				t.Errorf("got %q, want it to contain %q", got, c.survives)
			}
		})
	}
}

func TestDefaultRules_KeysDescribingASecretAreKept(t *testing.T) {
	r := Default()
	for _, in := range []string{
		`{"secretName":"tls-cert","token_type":"bearer","passwordPolicy":"strict"}`,
		`{"prompt_tokens":12,"author":"me","inside":1,"tokenizer":"bpe"}`,
		`{"api_key_id":"AKID","client_id":"web"}`,
		`<secretName>tls-cert</secretName>`,
		`secretName: tls-cert`,
		`app --token-file /var/run/token --password-stdin -u bob`,
		`app --password -v`,
	} {
		if got := r.RedactText(in); got != in {
			t.Errorf("RedactText(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestDefaultRules_ContainerKeyKeepsItsNonSecretMembers(t *testing.T) {
	got := Default().RedactText(`{"aws_credentials":{"user":"bob","secretKey":"hunter2"},"auth":["bob"]}`)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("still leaks: %q", got)
	}
	for _, keep := range []string{`"user":"bob"`, `"auth":["bob"]`, `"secretKey":"***"`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("got %q, want it to contain %q", got, keep)
		}
	}
}

func TestDefaultRules_EmptyCredentialValueIsLeftAlone(t *testing.T) {
	for _, in := range []string{`{"password":,"user":"bob"}`, `{"user":"bob","password": `} {
		if got := Default().RedactText(in); got != in {
			t.Errorf("RedactText(%q) = %q", in, got)
		}
	}
}

func TestRedact_RedisAuthArgumentsMasked(t *testing.T) {
	r := Default()
	for in, want := range map[string]string{
		"AUTH hunter2":                   "AUTH ***",
		"auth default hunter2":           "auth ***",
		"HELLO 3 AUTH default hunter2":   "HELLO 3 AUTH ***",
		"CONFIG SET requirepass hunter2": "CONFIG SET requirepass ***",
		"CONFIG SET masterauth hunter2":  "CONFIG SET masterauth ***",
		"AUTH %s":                        "AUTH ***",
		"GET k1\nAUTH hunter2\nGET k2":   "GET k1\nAUTH ***\nGET k2",
	} {
		e := &events.Event{Type: events.EventRedisCmd, Details: in}
		r.Redact(e)
		if e.Details != want {
			t.Errorf("Redact(%q) = %q, want %q", in, e.Details, want)
		}
	}
}

func TestRedact_RedisAuthRuleOnlyAppliesToRedisEvents(t *testing.T) {
	e := &events.Event{Type: events.EventMemcachedCmd, Details: "AUTH plain"}
	Default().Redact(e)
	if e.Details != "AUTH plain" {
		t.Fatalf("non-redis details changed: %q", e.Details)
	}
}

func TestKeyWordsSplitsNamingStyles(t *testing.T) {
	for in, want := range map[string]string{
		"db_password":                        "db password",
		"x-api-key":                          "x api key",
		"accessToken":                        "access token",
		"APIKey":                             "api key",
		"XMLHttpRequest":                     "xml http request",
		"aws.secret2Key":                     "aws secret2 key",
		"__":                                 "",
		"\u00dcn\u00efcode_Password\u00c4bc": "\u00fcn\u00efcode password \u00e4bc",
	} {
		if got := strings.Join(keyWords(in), " "); got != want {
			t.Errorf("keyWords(%q) = %q, want %q", in, got, want)
		}
	}
}
