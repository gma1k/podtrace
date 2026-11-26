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

func TestSendsHeaders(t *testing.T) {
	cases := map[string]struct {
		p    *Payload
		want bool
	}{
		"nil":             {nil, false},
		"none":            {&Payload{Type: TypeJaeger, Credential: []byte("k")}, false},
		"literal":         {&Payload{Headers: map[string]string{"a": "b"}}, true},
		"secret":          {&Payload{SecretHeaders: map[string]string{"a": "b"}}, true},
		"credential name": {&Payload{HeaderName: "Authorization"}, true},
	}
	for name, tc := range cases {
		if got := tc.p.SendsHeaders(); got != tc.want {
			t.Errorf("%s: SendsHeaders = %v, want %v", name, got, tc.want)
		}
	}
}

func TestSchemelessCleartext(t *testing.T) {
	tenant := map[string]string{"X-Scope-OrgID": "t"}
	cases := map[string]struct {
		p    *Payload
		want bool
	}{
		"nil":                     {nil, false},
		"otlp":                    {&Payload{Type: TypeOTLP}, false},
		"otlp insecure":           {&Payload{Type: TypeOTLP, Insecure: true}, true},
		"splunk":                  {&Payload{Type: TypeSplunk}, false},
		"datadog":                 {&Payload{Type: TypeDataDog}, false},
		"zipkin":                  {&Payload{Type: TypeZipkin}, true},
		"jaeger":                  {&Payload{Type: TypeJaeger}, true},
		"jaeger with headers":     {&Payload{Type: TypeJaeger, Headers: tenant}, false},
		"jaeger headers insecure": {&Payload{Type: TypeJaeger, Headers: tenant, Insecure: true}, true},
	}
	for name, tc := range cases {
		if got := tc.p.SchemelessCleartext(); got != tc.want {
			t.Errorf("%s: SchemelessCleartext = %v, want %v", name, got, tc.want)
		}
	}
}
