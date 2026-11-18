package config

import "testing"

func TestEgressProxySettingsTrimAndReportWhetherAProxyIsSet(t *testing.T) {
	t.Setenv(EnvEgressHTTPProxy, "")
	t.Setenv(EnvEgressHTTPSProxy, "  http://proxy:3128 ")
	t.Setenv(EnvEgressNoProxy, " .svc ")
	got := EgressProxySettings()
	if got != (EgressProxy{HTTPSProxy: "http://proxy:3128", NoProxy: ".svc"}) || !got.Set() {
		t.Fatalf("EgressProxySettings = %+v, set = %v", got, got.Set())
	}

	t.Setenv(EnvEgressHTTPSProxy, "")
	if EgressProxySettings().Set() {
		t.Fatal("a no-proxy list alone is not a proxy")
	}
}

func TestExporterInsecureOptsInWithoutTheEnvironment(t *testing.T) {
	t.Setenv("PODTRACE_EXPORTER_INSECURE", "")
	orig := ExporterInsecure
	t.Cleanup(func() { ExporterInsecure = orig })

	ExporterInsecure = false
	if ExporterAllowInsecureNonLoopback() {
		t.Fatal("cleartext allowed without an opt-in")
	}
	ExporterInsecure = true
	if !ExporterAllowInsecureNonLoopback() {
		t.Fatal("ExporterInsecure was ignored")
	}
}
