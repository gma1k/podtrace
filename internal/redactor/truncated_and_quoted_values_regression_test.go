package redactor

import (
	"strings"
	"testing"
)

func TestDefaultRules_TruncatedAndQuotedCredentialValues(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		leaked   string
		survives string
	}{
		{"json cut inside the value", `{"user":"bob","password":"hunter2-trunc`, "hunter2", `"user":"bob"`},
		{"json cut after an escape", `{"user":"bob","token":"abc\`, "abc", `"user":"bob"`},
		{"json number value", `{"token": 98765, "n": 1}`, "98765", `"n": 1`},
		{"json boolean value", `{"secret":true,"n":1}`, "true", `"n":1`},
		{"escaped json cut inside the value", `msg="{\"user\":\"bob\",\"password\":\"hunt`, "hunt", `\"user\":\"bob\"`},
		{"escaped json number value", `{\"token\":12345,\"n\":1}`, "12345", `\"n\":1`},
		{"kv single quoted with spaces", `password = 'correct horse battery' ok`, "horse", "ok"},
		{"kv double quoted with spaces", `user=bob&password="pw with space"&next=1`, "space", "next=1"},
		{"kv quoted value cut off", `user=bob password="never closed`, "closed", "user=bob"},
		{"single quoted key", `{'password': 'hunter2', 'user': 'bob'}`, "hunter2", `'user': 'bob'`},
		{"single quoted key bare value", `'token': 98765`, "98765", "token"},
		{"yaml double quoted with spaces", `password: "a b c" next`, "b c", "next"},
	}
	r := Default()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.RedactText(c.in)
			if strings.Contains(got, c.leaked) {
				t.Errorf("still leaks %q: %q", c.leaked, got)
			}
			if !strings.Contains(got, c.survives) {
				t.Errorf("lost non-secret context %q: %q", c.survives, got)
			}
		})
	}
}

func TestDefaultRules_NestedObjectUnderACredentialKeyIsNotSwallowed(t *testing.T) {
	got := Default().RedactText(`{"credentials": {"user":"bob","password":"x1y2"}}`)
	if strings.Contains(got, "x1y2") || !strings.Contains(got, `"user":"bob"`) {
		t.Fatalf("got %q", got)
	}
}
