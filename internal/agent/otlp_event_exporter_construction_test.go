package agent

import (
	"testing"

	"github.com/podtrace/podtrace/pkg/exporter/bundle"
)

func TestNewOTLPSpanExporter_URLPathSchemeAndSecretHeaders(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     bundle.TypeOTLP,
		Endpoint: cs.server.URL + "/custom/traces",
		SecretHeaders: map[string]string{
			"X-Secret-Scope": "team-a",
		},
		Headers: map[string]string{
			"X-Plain": "prod",
		},
	}

	exp, err := newOTLPEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("newOTLPEventExporter: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if cs.hitCount() == 0 {
		t.Fatal("capture server received no request")
	}
	if got := cs.lastPath(); got != "/custom/traces" {
		t.Errorf("request path = %q, want /custom/traces (WithURLPath)", got)
	}
	if got := cs.lastHeader("X-Secret-Scope"); got != "team-a" {
		t.Errorf("X-Secret-Scope header = %q, want team-a (Secret header merged)", got)
	}
	if got := cs.lastHeader("X-Plain"); got != "prod" {
		t.Errorf("X-Plain header = %q, want prod (literal header merged)", got)
	}
}

func TestNewOTLPSpanExporter_MissingEndpoint(t *testing.T) {
	if _, err := newOTLPSpanExporter(&BundlePayload{}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}
