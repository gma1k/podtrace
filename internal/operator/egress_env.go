package operator

import (
	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/config"
)

// egressEnv renders TracerConfig.spec.egress into the environment every
// podtrace container that exports, alerts or uploads reads. Nothing is
// rendered for an unset field, so the defaults stay the binary's own.
func egressEnv(tc *podtracev1alpha1.TracerConfig) []corev1.EnvVar {
	if tc == nil || tc.Spec.Egress == nil {
		return nil
	}
	e := tc.Spec.Egress
	var env []corev1.EnvVar
	if e.BlockPrivateRanges {
		env = append(env, corev1.EnvVar{Name: "PODTRACE_EXPORTER_BLOCK_PRIVATE", Value: "true"})
	}
	if p := e.Proxy; p != nil {
		for _, kv := range []struct{ name, value string }{
			{config.EnvEgressHTTPProxy, p.HTTPProxy},
			{config.EnvEgressHTTPSProxy, p.HTTPSProxy},
			{config.EnvEgressNoProxy, p.NoProxy},
		} {
			if kv.value != "" {
				env = append(env, corev1.EnvVar{Name: kv.name, Value: kv.value})
			}
		}
	}
	return env
}
