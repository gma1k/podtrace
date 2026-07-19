package operator

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func envValue(env []corev1.EnvVar, name string) (string, bool) {
	for _, e := range env {
		if e.Name == name {
			return e.Value, true
		}
	}
	return "", false
}

func TestBuildAgentDaemonSetSpec_OptionalAgentFields(t *testing.T) {
	dpcOff := false
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.ImagePullPolicy = corev1.PullAlways
		x.Spec.Agent.LogLevel = "debug"
		x.Spec.Agent.EventBufferSize = 4096
		x.Spec.Agent.DNSPacketCapture = &dpcOff
		x.Spec.Agent.StatusReportInterval = &metav1.Duration{Duration: 15 * time.Second}
	}), "podtrace-system")

	c := spec.Template.Spec.Containers[0]

	if c.ImagePullPolicy != corev1.PullAlways {
		t.Errorf("ImagePullPolicy=%q want Always", c.ImagePullPolicy)
	}
	if v, ok := envValue(c.Env, "PODTRACE_LOG_LEVEL"); !ok || v != "debug" {
		t.Errorf("PODTRACE_LOG_LEVEL=%q ok=%v want debug", v, ok)
	}
	if v, ok := envValue(c.Env, "PODTRACE_EVENT_BUFFER_SIZE"); !ok || v != "4096" {
		t.Errorf("PODTRACE_EVENT_BUFFER_SIZE=%q ok=%v want 4096", v, ok)
	}
	if v, ok := envValue(c.Env, "PODTRACE_DNS_PACKET_CAPTURE"); !ok || v != "false" {
		t.Errorf("PODTRACE_DNS_PACKET_CAPTURE=%q ok=%v want false", v, ok)
	}

	joined := ""
	for _, a := range c.Args {
		joined += a + " "
	}
	if !contains(joined, "--status-report-interval 15s") {
		t.Errorf("--status-report-interval not wired: %v", c.Args)
	}
}

func TestBuildAgentDaemonSetSpec_CapabilitySwitches(t *testing.T) {
	on := true
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.USDT = &on
		x.Spec.Agent.DNSFullAnswers = &on
	}), "podtrace-system")
	env := spec.Template.Spec.Containers[0].Env

	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want true", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want true", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_CapabilityDefaults(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {}), "podtrace-system")
	env := spec.Template.Spec.Containers[0].Env
	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want true (default on)", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want true (default on)", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_CapabilityExplicitDisable(t *testing.T) {
	off := false
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.USDT = &off
		x.Spec.Agent.DNSFullAnswers = &off
	}), "podtrace-system")
	env := spec.Template.Spec.Containers[0].Env
	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "false" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want false (explicit disable)", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "false" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want false (explicit disable)", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_DNSPacketCaptureEnabledOmitsEnv(t *testing.T) {
	dpcOn := true
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.DNSPacketCapture = &dpcOn
	}), "podtrace-system")
	if _, ok := envValue(spec.Template.Spec.Containers[0].Env, "PODTRACE_DNS_PACKET_CAPTURE"); ok {
		t.Error("PODTRACE_DNS_PACKET_CAPTURE must be absent when capture is enabled")
	}
}
