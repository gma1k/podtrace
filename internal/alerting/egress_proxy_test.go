package alerting

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestAlertsGoThroughThePodtraceEgressProxy(t *testing.T) {
	t.Setenv("PODTRACE_EGRESS_HTTPS_PROXY", "http://proxy.corp:3128")
	t.Setenv("PODTRACE_EGRESS_HTTP_PROXY", "")
	t.Setenv("PODTRACE_EGRESS_NO_PROXY", "")

	client := newAlertHTTPClient(time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy == nil {
		t.Fatalf("alert transport = %T without a proxy hook", client.Transport)
	}
	u, _ := url.Parse("https://hooks.slack.com/services/x")
	got, err := transport.Proxy(&http.Request{URL: u})
	if err != nil || got == nil || got.String() != "http://proxy.corp:3128" {
		t.Fatalf("proxy = %v, err = %v", got, err)
	}
	if client.CheckRedirect == nil {
		t.Fatal("the alert client must still refuse redirects")
	}
}
