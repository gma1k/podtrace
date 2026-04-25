package config

import "testing"

func TestOTLPAllowInsecureNonLoopback(t *testing.T) {
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	if OTLPAllowInsecureNonLoopback() {
		t.Error("expected false when env unset")
	}
	t.Setenv("PODTRACE_OTLP_INSECURE", "1")
	if !OTLPAllowInsecureNonLoopback() {
		t.Error("expected true when env=1")
	}
	t.Setenv("PODTRACE_OTLP_INSECURE", "0")
	if OTLPAllowInsecureNonLoopback() {
		t.Error("env=0 must not enable insecure")
	}
}

func TestMetricsEnablePprof(t *testing.T) {
	old := ProfilingEnabled
	defer func() { ProfilingEnabled = old }()

	ProfilingEnabled = false
	t.Setenv("PODTRACE_METRICS_ENABLE_PPROF", "")
	if MetricsEnablePprof() {
		t.Error("default should be false")
	}
	t.Setenv("PODTRACE_METRICS_ENABLE_PPROF", "1")
	if !MetricsEnablePprof() {
		t.Error("env=1 should enable pprof")
	}

	t.Setenv("PODTRACE_METRICS_ENABLE_PPROF", "")
	ProfilingEnabled = true
	if !MetricsEnablePprof() {
		t.Error("ProfilingEnabled=true should also enable pprof")
	}
}

func TestSplunkAlertAllowHTTP(t *testing.T) {
	t.Setenv("PODTRACE_ALERT_SPLUNK_ALLOW_HTTP", "")
	if SplunkAlertAllowHTTP() {
		t.Error("default should be false")
	}
	t.Setenv("PODTRACE_ALERT_SPLUNK_ALLOW_HTTP", "1")
	if !SplunkAlertAllowHTTP() {
		t.Error("env=1 should allow http")
	}
	t.Setenv("PODTRACE_ALERT_SPLUNK_ALLOW_HTTP", "true")
	if SplunkAlertAllowHTTP() {
		t.Error("only literal '1' should allow http (defensive)")
	}
}

func TestAllowCgroupFilterAutoDisable(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", "")
	if AllowCgroupFilterAutoDisable() {
		t.Error("default should be false")
	}
	t.Setenv("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", "1")
	if !AllowCgroupFilterAutoDisable() {
		t.Error("env=1 should enable")
	}
}
