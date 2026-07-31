package config

import "testing"

// TestGetBoolEnvOrDefault_AcceptedForms: only lowercase "true" used to
// count; "TRUE", "True", and "1" silently read as false.
func TestGetBoolEnvOrDefault_AcceptedForms(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"true", true}, {"TRUE", true}, {"True", true}, {"1", true}, {"t", true},
		{"false", false}, {"FALSE", false}, {"0", false},
		{"garbage", true}, // unparsable keeps the default (true here)
		{" true ", true},  // surrounding whitespace tolerated
	}
	for _, c := range cases {
		t.Setenv("PODTRACE_TEST_BOOL", c.value)
		if got := getBoolEnvOrDefault("PODTRACE_TEST_BOOL", true); got != c.want {
			t.Errorf("getBoolEnvOrDefault(%q, true) = %v, want %v", c.value, got, c.want)
		}
	}
	t.Setenv("PODTRACE_TEST_BOOL", "garbage")
	if got := getBoolEnvOrDefault("PODTRACE_TEST_BOOL", false); got != false {
		t.Error("unparsable value must keep the default (false)")
	}
}

func TestBoolAccessors_FailClosedOnEverySpelling(t *testing.T) {
	accessors := []struct {
		key          string
		fn           func() bool
		defaultValue bool
	}{
		{"PODTRACE_REDACT_DNS_NAMES", RedactDNSNames, false},
		{"PODTRACE_DNS_PACKET_CAPTURE", DNSPacketCaptureEnabled, true},
		{"PODTRACE_K8S_ENRICHMENT_ENABLED", K8sEnrichmentEnabled, true},
		{"PODTRACE_K8S_USE_INFORMERS", K8sUseInformers, true},
		{"PODTRACE_CRI_RESOLVE", CRIResolveEnabled, true},
	}

	truthy := []string{"true", "TRUE", "True", "1", "t"}
	falsy := []string{"false", "FALSE", "False", "0", "f"}

	for _, a := range accessors {
		t.Run(a.key, func(t *testing.T) {
			for _, v := range truthy {
				t.Setenv(a.key, v)
				if !a.fn() {
					t.Errorf("%s=%q must read as true", a.key, v)
				}
			}
			for _, v := range falsy {
				t.Setenv(a.key, v)
				if a.fn() {
					t.Errorf("%s=%q must read as false", a.key, v)
				}
			}
			t.Setenv(a.key, "")
			if got := a.fn(); got != a.defaultValue {
				t.Errorf("%s unset = %v, want default %v", a.key, got, a.defaultValue)
			}
			t.Setenv(a.key, "definitely-not-a-bool")
			if got := a.fn(); got != a.defaultValue {
				t.Errorf("%s unparsable = %v, want default %v", a.key, got, a.defaultValue)
			}
		})
	}
}
