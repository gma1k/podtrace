package netguard

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func requestTo(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{URL: u}
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PODTRACE_EGRESS_HTTP_PROXY", "PODTRACE_EGRESS_HTTPS_PROXY", "PODTRACE_EGRESS_NO_PROXY",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "REQUEST_METHOD",
	} {
		t.Setenv(k, "")
	}
}

func TestEgressProxyUsesThePodtraceProxyPerScheme(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", "http://plain-proxy:3128")
	t.Setenv("PODTRACE_EGRESS_HTTPS_PROXY", "http://tls-proxy:3128")
	t.Setenv("PODTRACE_EGRESS_NO_PROXY", ".svc.cluster.local")

	for target, want := range map[string]string{
		"http://collector.example.com:4318":            "http://plain-proxy:3128",
		"https://collector.example.com:4318":           "http://tls-proxy:3128",
		"https://otel.observability.svc.cluster.local": "",
	} {
		got, err := EgressProxy(requestTo(t, target))
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if (got == nil && want != "") || (got != nil && got.String() != want) {
			t.Errorf("%s: proxy = %v, want %q", target, got, want)
		}
	}
}

func TestEgressProxyFallsBackToTheStandardEnvironment(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EGRESS_NO_PROXY", "example.com")
	t.Setenv("HTTPS_PROXY", "http://standard-proxy:8080")

	got, err := EgressProxy(requestTo(t, "https://collector.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != "http://standard-proxy:8080" {
		t.Fatalf("proxy = %v; with no podtrace proxy set the standard environment applies", got)
	}
}

func TestEgressProxyOverridesTheStandardEnvironment(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://standard-proxy:8080")
	t.Setenv("PODTRACE_EGRESS_HTTPS_PROXY", "http://podtrace-proxy:3128")

	got, err := EgressProxy(requestTo(t, "https://collector.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != "http://podtrace-proxy:3128" {
		t.Fatalf("proxy = %v", got)
	}
}

func TestTheHardenedClientSendsExporterTrafficThroughThePodtraceProxy(t *testing.T) {
	clearProxyEnv(t)
	proxy, hits := newRecordingProxy(t)
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", proxy.URL)
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}

	resp, err := HardenedClient(5 * time.Second).Get("http://collector.example.test/v1/traces")
	if err != nil {
		t.Fatalf("GET through the podtrace proxy: %v", err)
	}
	_ = resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("proxy hits = %d, want 1", hits.Load())
	}
}

func TestThePodtraceProxyDoesNotBypassTheAddressGuard(t *testing.T) {
	clearProxyEnv(t)
	proxy, hits := newRecordingProxy(t)
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", proxy.URL)

	if _, err := HardenedClient(5 * time.Second).Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Fatal("a metadata address was reached through the podtrace proxy")
	}
	if hits.Load() != 0 {
		t.Fatalf("proxy hits = %d, want 0", hits.Load())
	}
}
