package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestProxyDialAddress(t *testing.T) {
	cases := map[string]string{
		"":                           "",
		"http://Proxy.Corp:3128":     "proxy.corp:3128",
		"http://proxy.corp":          "proxy.corp:80",
		"https://proxy.corp":         "proxy.corp:443",
		"socks5://proxy.corp":        "proxy.corp:1080",
		"proxy.corp:3128":            "proxy.corp:3128",
		"http://[fd00::1]:3128/path": "[fd00::1]:3128",
		"http://%zz":                 "",
	}
	for raw, want := range cases {
		if got := proxyDialAddress(raw); got != want {
			t.Errorf("proxyDialAddress(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestIsEgressProxyAddressUsesThePodtraceProxyFirst(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://standard:8080")
	t.Setenv("PODTRACE_EGRESS_HTTPS_PROXY", "http://10.0.0.5:3128")

	if !isEgressProxyAddress("10.0.0.5:3128") {
		t.Fatal("the podtrace proxy address was not recognised")
	}
	if isEgressProxyAddress("standard:8080") {
		t.Fatal("the standard proxy was recognised although a podtrace proxy is set")
	}
	if isEgressProxyAddress("10.0.0.5:3129") {
		t.Fatal("another port on the proxy host was recognised as the proxy")
	}
}

func TestIsEgressProxyAddressFallsBackToTheStandardProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://Corp-Proxy:3128")
	if !isEgressProxyAddress("corp-proxy:3128") {
		t.Fatal("the standard proxy address was not recognised")
	}
}

func TestAPrivateProxyIsDialableWhilePrivateTargetsStayBlocked(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")

	if err := controlBlockSSRF("tcp", "10.0.0.5:3128", nil); !errors.Is(err, ErrBlocked) {
		t.Fatalf("a private target must stay blocked, got %v", err)
	}
	if err := controlBlockAlways("tcp", "10.0.0.5:3128", nil); err != nil {
		t.Fatalf("the configured proxy on a private address was refused: %v", err)
	}
	if err := controlBlockAlways("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrBlocked) {
		t.Fatalf("a proxy on the metadata address must be refused, got %v", err)
	}
	if err := controlBlockAlways("tcp", "not-an-ip:80", nil); !errors.Is(err, ErrBlocked) {
		t.Fatalf("an unresolved dial address must be refused, got %v", err)
	}
	if err := controlBlockAlways("tcp", "missing-port", nil); err == nil {
		t.Fatal("a malformed dial address was accepted")
	}
}

func TestAProxiedPrivateTargetIsStillRefused(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", "http://10.0.0.5:3128")

	u, _ := url.Parse("http://10.1.2.3:4318/v1/traces")
	req := (&http.Request{URL: u}).WithContext(context.Background())
	if _, err := guardedProxy(req); !errors.Is(err, ErrBlocked) {
		t.Fatalf("a private target reached through the proxy must be refused, got %v", err)
	}
}

func TestDialGuardedRelaxesOnlyTheProxyAddress(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", "http://127.0.0.1:1")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	conn, err := dialGuarded(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("a loopback dial was refused: %v", err)
	}
	_ = conn.Close()

	if _, err := dialGuarded(context.Background(), "tcp", "10.255.255.1:9"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("a private non-proxy address was dialled, got %v", err)
	}
}

func TestADirectRequestToTheProxyAddressIsStillCheckedForPrivateRanges(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", "http://10.0.0.5:3128")
	t.Setenv("PODTRACE_EGRESS_NO_PROXY", "10.0.0.5")

	u, _ := url.Parse("http://10.0.0.5:3128/v1/traces")
	got, err := guardedProxy((&http.Request{URL: u}).WithContext(context.Background()))
	if !errors.Is(err, ErrBlocked) || got != nil {
		t.Fatalf("a tenant endpoint naming the proxy address bypassed the private-range check: proxy=%v err=%v", got, err)
	}
	if !strings.Contains(err.Error(), "exporter request to the proxy address") {
		t.Fatalf("the refusal does not say it was a direct request to the proxy address: %v", err)
	}
}

func TestADirectRequestToAnotherPublicAddressIsNotResolved(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", "http://10.0.0.5:3128")
	t.Setenv("PODTRACE_EGRESS_NO_PROXY", "collector.example.com")

	u, _ := url.Parse("http://collector.example.com:4318/v1/traces")
	got, err := guardedProxy((&http.Request{URL: u}).WithContext(context.Background()))
	if err != nil || got != nil {
		t.Fatalf("direct request: proxy=%v err=%v", got, err)
	}
}

func TestAProxyLookupErrorIsReturned(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", "http://proxy:3128")
	u := &url.URL{Scheme: "http", Host: "collector:4318", Path: "/"}
	orig := proxyFromEnvironment
	t.Cleanup(func() { proxyFromEnvironment = orig })
	proxyFromEnvironment = func(*http.Request) (*url.URL, error) { return nil, errors.New("bad proxy") }
	if _, err := guardedProxy(&http.Request{URL: u}); err == nil || err.Error() != "bad proxy" {
		t.Fatalf("err = %v", err)
	}
}
