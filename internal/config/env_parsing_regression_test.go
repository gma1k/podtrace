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
