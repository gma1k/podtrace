package operator

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func egressTracerConfig(egress *podtracev1alpha1.EgressSpec) *podtracev1alpha1.TracerConfig {
	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"}}
	tc.Spec.Egress = egress
	tc.Spec.Session.SidecarUploader = true
	return tc
}

var fullEgress = &podtracev1alpha1.EgressSpec{
	BlockPrivateRanges: true,
	Proxy: &podtracev1alpha1.EgressProxySpec{
		HTTPProxy:  "http://proxy.corp:3128",
		HTTPSProxy: "http://proxy.corp:3128",
		NoProxy:    ".svc,.cluster.local,10.0.0.0/8",
	},
}

var fullEgressEnv = map[string]string{
	"PODTRACE_EXPORTER_BLOCK_PRIVATE": "true",
	"PODTRACE_EGRESS_HTTP_PROXY":      "http://proxy.corp:3128",
	"PODTRACE_EGRESS_HTTPS_PROXY":     "http://proxy.corp:3128",
	"PODTRACE_EGRESS_NO_PROXY":        ".svc,.cluster.local,10.0.0.0/8",
}

func assertEgressEnv(t *testing.T, where string, env []corev1.EnvVar) {
	t.Helper()
	got := envMap(env)
	for k, v := range fullEgressEnv {
		if got[k] != v {
			t.Errorf("%s: %s = %q, want %q", where, k, got[k], v)
		}
	}
}

func TestEgressEnvRendersNothingWhenUnset(t *testing.T) {
	for name, tc := range map[string]*podtracev1alpha1.TracerConfig{
		"nil tracerconfig": nil,
		"no egress":        egressTracerConfig(nil),
		"empty egress":     egressTracerConfig(&podtracev1alpha1.EgressSpec{}),
		"empty proxy":      egressTracerConfig(&podtracev1alpha1.EgressSpec{Proxy: &podtracev1alpha1.EgressProxySpec{}}),
	} {
		t.Run(name, func(t *testing.T) {
			if env := egressEnv(tc); len(env) != 0 {
				t.Fatalf("egressEnv = %v", env)
			}
		})
	}
}

func TestEgressEnvRendersOnlySetFields(t *testing.T) {
	env := egressEnv(egressTracerConfig(&podtracev1alpha1.EgressSpec{
		Proxy: &podtracev1alpha1.EgressProxySpec{HTTPSProxy: "http://proxy:3128"},
	}))
	want := []corev1.EnvVar{{Name: "PODTRACE_EGRESS_HTTPS_PROXY", Value: "http://proxy:3128"}}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("egressEnv = %v, want %v", env, want)
	}
}

func TestTheAgentDaemonSetCarriesTheEgressSettings(t *testing.T) {
	spec := buildAgentDaemonSetSpec(egressTracerConfig(fullEgress), "podtrace-system")
	assertEgressEnv(t, "agent", spec.Template.Spec.Containers[0].Env)
}

func TestASessionJobAndItsUploaderCarryTheEgressSettings(t *testing.T) {
	spec := buildSessionJobSpec(sessionWithObjectStore(""), egressTracerConfig(fullEgress), "node-a", sessionTargets{})
	assertEgressEnv(t, "session", spec.Template.Spec.Containers[0].Env)
	if len(spec.Template.Spec.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want the report uploader", len(spec.Template.Spec.InitContainers))
	}
	assertEgressEnv(t, "report-uploader", spec.Template.Spec.InitContainers[0].Env)
}

func TestASessionJobNoLongerLiftsTheCleartextGuardForEveryExporter(t *testing.T) {
	spec := buildSessionJobSpec(newSession(nil), egressTracerConfig(nil), "node-a", sessionTargets{})
	env := envMap(spec.Template.Spec.Containers[0].Env)
	for _, name := range []string{"PODTRACE_OTLP_INSECURE", "PODTRACE_EXPORTER_INSECURE"} {
		if v, ok := env[name]; ok {
			t.Errorf("%s = %q; cleartext must follow the session's ExporterConfig, not a Job-wide override", name, v)
		}
	}
}
