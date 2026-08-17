package config

import "testing"

func TestGetBoolEnvOrDefault_AcceptedForms(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"true", true}, {"TRUE", true}, {"True", true}, {"1", true}, {"t", true},
		{"false", false}, {"FALSE", false}, {"0", false},
		{"yes", true}, {"YES", true}, {"on", true}, {"On", true},
		{"enable", true}, {"enabled", true}, {"ENABLED", true}, {"y", true},
		{"no", false}, {"NO", false}, {"off", false}, {"Off", false},
		{"disable", false}, {"disabled", false}, {"n", false},
		{"garbage", true},
		{" true ", true},
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

func TestRedactPII_HumanTruthyEnablesRedaction(t *testing.T) {
	const key = "PODTRACE_REDACT_PII"
	for _, v := range []string{"yes", "YES", "on", "enabled", "enable", "y", "true", "1"} {
		t.Setenv(key, v)
		if !getBoolEnvOrDefault(key, false) {
			t.Errorf("%s=%q must enable redaction (fail-open regression)", key, v)
		}
	}
	for _, v := range []string{"no", "off", "disabled", "false", "0", "n"} {
		t.Setenv(key, v)
		if getBoolEnvOrDefault(key, false) {
			t.Errorf("%s=%q must keep redaction off", key, v)
		}
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
