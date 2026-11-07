package redactor

import (
	"strings"
	"testing"
)

const (
	awsAccessKeyPrefix      = "AK" + "IA"
	awsSessionKeyPrefix     = "AS" + "IA"
	githubTokenPrefix       = "gh" + "p_"
	githubFineGrainedPrefix = "github" + "_pat_"
	slackBotPrefix          = "xo" + "xb-"
	stripeLivePrefix        = "sk" + "_live_"
)

func TestDefaultRules_BareTokenFormats(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		leaked   string
		survives string
	}{
		{"pem private key", "key loaded -----BEGIN RSA PRIVATE KEY-----\nMIIEsecretbody\n-----END RSA PRIVATE KEY----- done", "MIIEsecretbody", "done"},
		{"pem private key cut off", "cfg -----BEGIN PRIVATE KEY-----\nMIIEtruncated", "MIIEtruncated", "cfg"},
		{"jwt in a path", "GET /api/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl HTTP/1.1", "eyJzdWIiOiIxIn0", "HTTP/1.1"},
		{"aws access key id", "using " + awsAccessKeyPrefix + "IOSFODNN7EXAMPLE for s3", "IOSFODNN7EXAMPLE", "for s3"},
		{"aws session key id", "using " + awsSessionKeyPrefix + "IOSFODNN7EXAMPLE for s3", "IOSFODNN7EXAMPLE", "for s3"},
		{"aws key id longer than twenty", "GET /s3/" + awsAccessKeyPrefix + "LEAKFODNN7EXAMPLE HTTP/1.1", "LEAKFODNN7EXAMPLE", "/s3/"},
		{"aws key id at the sixteen minimum", "id " + awsAccessKeyPrefix + "2E0A8F3B244C done", "2E0A8F3B244C", "done"},
		{"github token", "clone with " + githubTokenPrefix + "abcdefghijklmnopqrstuvwxyz0123456789 now", "abcdefghijklmnop", "now"},
		{"github fine grained token", "pat " + githubFineGrainedPrefix + "11ABCDEFG0123456789_abcdefghijklmnop end", "11ABCDEFG", "end"},
		{"slack token", "slack " + slackBotPrefix + "1234567890-abcdefghij end", "1234567890", "end"},
		{"stripe key", "charge " + stripeLivePrefix + "abcdefghijkl0123 ok", "abcdefghijkl", "ok"},
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

func TestDefaultRules_PublicKeysAndLookalikesAreKept(t *testing.T) {
	r := Default()
	for _, in := range []string{
		"-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----",
		"-----BEGIN PUBLIC KEY-----\nMIIBpub\n-----END PUBLIC KEY-----",
		"AKIA is a prefix",
		"ghp_short",
	} {
		if got := r.RedactText(in); got != in {
			t.Errorf("RedactText(%q) = %q, want unchanged", in, got)
		}
	}
}
