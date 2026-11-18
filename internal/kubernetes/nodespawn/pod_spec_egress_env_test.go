package nodespawn

import "testing"

func TestBuildPodSpec_ForwardsExporterEgressEnvironment(t *testing.T) {
	want := map[string]string{
		"PODTRACE_EXPORTER_INSECURE":      "1",
		"PODTRACE_EXPORTER_BLOCK_PRIVATE": "true",
		"PODTRACE_EGRESS_HTTP_PROXY":      "http://proxy:3128",
		"PODTRACE_EGRESS_HTTPS_PROXY":     "http://proxy:3129",
		"PODTRACE_EGRESS_NO_PROXY":        ".svc",
	}
	for k, v := range want {
		t.Setenv(k, v)
	}

	pod, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("BuildPodSpec: %v", err)
	}
	got := map[string]string{}
	for _, e := range pod.Spec.Containers[0].Env {
		got[e.Name] = e.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
