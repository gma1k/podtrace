package operator

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestRedactionEnv_NilAndDisabled(t *testing.T) {
	if env := redactionEnv(nil); env != nil {
		t.Errorf("nil spec: want no env, got %v", env)
	}
	if env := redactionEnv(&podtracev1alpha1.RedactionSpec{Enabled: false}); env != nil {
		t.Errorf("disabled spec: want no env, got %v", env)
	}
}

func TestRedactionEnv_EnabledMinimal(t *testing.T) {
	env := redactionEnv(&podtracev1alpha1.RedactionSpec{Enabled: true})
	if v, ok := envValue(env, "PODTRACE_REDACT_PII"); !ok || v != "true" {
		t.Errorf("PODTRACE_REDACT_PII=%q ok=%v want true", v, ok)
	}
	if _, ok := envValue(env, "PODTRACE_REDACT_DNS_NAMES"); ok {
		t.Error("PODTRACE_REDACT_DNS_NAMES must be absent when not requested")
	}
	if _, ok := envValue(env, "PODTRACE_REDACT_CUSTOM_RULES"); ok {
		t.Error("PODTRACE_REDACT_CUSTOM_RULES must be absent when no custom rules")
	}
}

func TestRedactionEnv_DNSNamesAndCustomRules(t *testing.T) {
	env := redactionEnv(&podtracev1alpha1.RedactionSpec{
		Enabled:        true,
		RedactDNSNames: true,
		CustomRules: []podtracev1alpha1.RedactionRule{
			{Name: "ssn", Pattern: `\d{3}-\d{2}-\d{4}`, Replace: "***-**-****"},
		},
	})
	if v, ok := envValue(env, "PODTRACE_REDACT_DNS_NAMES"); !ok || v != "true" {
		t.Errorf("PODTRACE_REDACT_DNS_NAMES=%q ok=%v want true", v, ok)
	}
	raw, ok := envValue(env, "PODTRACE_REDACT_CUSTOM_RULES")
	if !ok {
		t.Fatal("PODTRACE_REDACT_CUSTOM_RULES missing")
	}
	var got []map[string]string
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("custom rules not valid JSON: %v (%q)", err, raw)
	}
	if len(got) != 1 || got[0]["name"] != "ssn" || got[0]["pattern"] != `\d{3}-\d{2}-\d{4}` || got[0]["replace"] != "***-**-****" {
		t.Errorf("unexpected serialized rules: %q", raw)
	}
}

func TestBuildAgentDaemonSetSpec_Redaction(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Redaction = &podtracev1alpha1.RedactionSpec{Enabled: true, RedactDNSNames: true}
	}), "podtrace-system")
	env := spec.Template.Spec.Containers[0].Env
	if v, ok := envValue(env, "PODTRACE_REDACT_PII"); !ok || v != "true" {
		t.Errorf("agent PODTRACE_REDACT_PII=%q ok=%v want true", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_REDACT_DNS_NAMES"); !ok || v != "true" {
		t.Errorf("agent PODTRACE_REDACT_DNS_NAMES=%q ok=%v want true", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_RedactionAbsentByDefault(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	if _, ok := envValue(spec.Template.Spec.Containers[0].Env, "PODTRACE_REDACT_PII"); ok {
		t.Error("PODTRACE_REDACT_PII must be absent when redaction is unset")
	}
}

func TestBuildSessionJobSpec_Redaction(t *testing.T) {
	tcfg := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:     "ghcr.io/gma1k/podtrace:test",
			Redaction: &podtracev1alpha1.RedactionSpec{Enabled: true},
		},
	}
	spec := buildSessionJobSpec(newSession(nil), tcfg, "node-a", nil)
	var mainEnv []corev1.EnvVar
	for _, c := range spec.Template.Spec.Containers {
		if c.Name == "podtrace" {
			mainEnv = c.Env
		}
	}
	if v, ok := envValue(mainEnv, "PODTRACE_REDACT_PII"); !ok || v != "true" {
		t.Errorf("session PODTRACE_REDACT_PII=%q ok=%v want true", v, ok)
	}
}
