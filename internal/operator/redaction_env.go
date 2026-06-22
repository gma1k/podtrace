package operator

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// redactionEnv translates a TracerConfig's redaction settings into the env
// vars the tracer reads (PODTRACE_REDACT_PII / _DNS_NAMES / _CUSTOM_RULES).
func redactionEnv(r *podtracev1alpha1.RedactionSpec) []corev1.EnvVar {
	if r == nil || !r.Enabled {
		return nil
	}
	env := []corev1.EnvVar{{Name: "PODTRACE_REDACT_PII", Value: "true"}}
	if r.RedactDNSNames {
		env = append(env, corev1.EnvVar{Name: "PODTRACE_REDACT_DNS_NAMES", Value: "true"})
	}
	if len(r.CustomRules) > 0 {
		type ruleJSON struct {
			Name    string `json:"name"`
			Pattern string `json:"pattern"`
			Replace string `json:"replace"`
		}
		rules := make([]ruleJSON, 0, len(r.CustomRules))
		for _, cr := range r.CustomRules {
			rules = append(rules, ruleJSON{Name: cr.Name, Pattern: cr.Pattern, Replace: cr.Replace})
		}
		if b, err := json.Marshal(rules); err == nil {
			env = append(env, corev1.EnvVar{Name: "PODTRACE_REDACT_CUSTOM_RULES", Value: string(b)})
		}
	}
	return env
}
