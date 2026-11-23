package bundle

import (
	"strings"
	"testing"
)

func TestBundleAcceptsTheKnownProtocols(t *testing.T) {
	for _, protocol := range []string{"", ProtocolHTTP, ProtocolGRPC} {
		data := map[string]string{"type": "otlp", "endpoint": "otel:4317"}
		if protocol != "" {
			data["protocol"] = protocol
		}
		p, err := FromConfigMapData(data)
		if err != nil {
			t.Fatalf("protocol %q: %v", protocol, err)
		}
		if got := p.UsesGRPC(); got != (protocol == ProtocolGRPC) {
			t.Errorf("protocol %q: UsesGRPC = %v", protocol, got)
		}
	}
}

func TestBundleRefusesAnUnknownProtocol(t *testing.T) {
	_, err := FromConfigMapData(map[string]string{"type": "otlp", "endpoint": "otel:4317", "protocol": "http/protobuf"})
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("err = %v, want the unsupported protocol refusal", err)
	}
	if _, err := FromYAML([]byte("type: otlp\nendpoint: otel:4317\nprotocol: quic\n")); err == nil {
		t.Fatal("a YAML bundle with an unknown protocol was accepted")
	}
}

func TestProtocolSurvivesTheYAMLRoundTrip(t *testing.T) {
	p, err := FromConfigMapData(map[string]string{"type": "otlp", "endpoint": "otel:4317", "protocol": "grpc"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ToYAML(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !back.UsesGRPC() {
		t.Errorf("protocol lost across the session bundle YAML: %+v", back)
	}
}
