package agent

import (
	"testing"

	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestASchemelessJaegerEndpointReachesAPlaintextCollector(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{Type: bundle.TypeJaeger, Endpoint: cs.endpointHostPort()}
	exp, err := newJaegerEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if cs.hitCount() == 0 {
		t.Fatal("a scheme-less Jaeger endpoint must be reached over http, as session Jobs reach it")
	}
	if b.Insecure {
		t.Fatal("building the exporter changed the shared bundle payload")
	}
}

func TestASchemelessJaegerEndpointWithHeadersUsesTLS(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     bundle.TypeJaeger,
		Endpoint: cs.endpointHostPort(),
		Headers:  map[string]string{"X-Scope-OrgID": "tenant-a"},
	}
	exp, err := newJaegerEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if cs.hitCount() != 0 {
		t.Fatal("headers reached a plaintext collector: a Jaeger exporter that sends headers must use TLS")
	}
}

func TestAnExplicitHTTPJaegerEndpointWithHeadersStaysCleartext(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     bundle.TypeJaeger,
		Endpoint: "http://" + cs.endpointHostPort(),
		Headers:  map[string]string{"X-Scope-OrgID": "tenant-a"},
	}
	exp, err := newJaegerEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if got := cs.lastHeader("X-Scope-OrgID"); got != "tenant-a" {
		t.Fatalf("X-Scope-OrgID = %q, want tenant-a over the http:// the ExporterConfig named", got)
	}
}
