package operator

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func minimalSession() *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-opt"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
}

func TestBuildSessionJobSpec_ImagePullPolicyOverride(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:           "ghcr.io/gma1k/podtrace:test",
			ImagePullPolicy: corev1.PullAlways,
		},
	}
	spec := buildSessionJobSpec(minimalSession(), tc, "node-a", sessionTargets{})
	if got := spec.Template.Spec.Containers[0].ImagePullPolicy; got != corev1.PullAlways {
		t.Errorf("ImagePullPolicy = %q, want Always", got)
	}
}

func TestBuildSessionJobSpec_MainContainerAgentEnvFromTracerConfig(t *testing.T) {
	usdtOff := false
	dnsOff := false
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:test",
			Agent: podtracev1alpha1.AgentSpec{
				USDT:           &usdtOff,
				DNSFullAnswers: &dnsOff,
				LogLevel:       "debug",
			},
		},
	}
	spec := buildSessionJobSpec(minimalSession(), tc, "node-a", sessionTargets{})
	env := spec.Template.Spec.Containers[0].Env

	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "false" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want false", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "false" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want false", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_LOG_LEVEL"); !ok || v != "debug" {
		t.Errorf("PODTRACE_LOG_LEVEL=%q ok=%v want debug", v, ok)
	}
}

func TestBuildSessionJobSpec_AgentEnvDefaultsWhenUnset(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
	}
	spec := buildSessionJobSpec(minimalSession(), tc, "node-a", sessionTargets{})
	env := spec.Template.Spec.Containers[0].Env

	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want true (default)", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want true (default)", v, ok)
	}
	if _, ok := envValue(env, "PODTRACE_LOG_LEVEL"); ok {
		t.Error("PODTRACE_LOG_LEVEL must be absent when LogLevel is unset")
	}
}
