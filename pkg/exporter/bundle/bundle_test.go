package bundle

import (
	"reflect"
	"strings"
	"testing"
)

func TestFromConfigMapData_OTLPLiteralHeaders(t *testing.T) {
	data := map[string]string{
		"type":             "otlp",
		"endpoint":         "otel:4318",
		"protocol":         "http",
		"insecure":         "false",
		"headers.X-Env":    "prod",
		"headers.X-Tenant": "team-a",
		"sample_percent":   "50",
	}
	p, err := FromConfigMapData(data)
	if err != nil {
		t.Fatalf("FromConfigMapData: %v", err)
	}
	if p.Type != TypeOTLP || p.Endpoint != "otel:4318" {
		t.Errorf("payload wrong: %+v", p)
	}
	if p.Sample != 0.5 {
		t.Errorf("sample=%v want 0.5", p.Sample)
	}
	if p.Headers["X-Env"] != "prod" || p.Headers["X-Tenant"] != "team-a" {
		t.Errorf("headers lost: %+v", p.Headers)
	}
	if p.Insecure {
		t.Error("insecure parsed wrong for 'false'")
	}
}

func TestFromConfigMapData_NilInputErrors(t *testing.T) {
	_, err := FromConfigMapData(nil)
	if err == nil {
		t.Fatal("expected error on nil data")
	}
}

func TestFromConfigMapData_DataDogSite(t *testing.T) {
	p, err := FromConfigMapData(map[string]string{"type": "datadog", "site": "datadoghq.eu"})
	if err != nil {
		t.Fatalf("FromConfigMapData: %v", err)
	}
	if p.Type != TypeDataDog || p.Site != "datadoghq.eu" {
		t.Errorf("datadog payload wrong: %+v", p)
	}
}

func TestFromConfigMapData_SampleBadValuesRejected(t *testing.T) {
	cases := []string{"abc", "-1", "101"}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			if _, err := FromConfigMapData(map[string]string{"type": "otlp", "sample_percent": v}); err == nil {
				t.Fatalf("expected error for sample_percent=%q", v)
			}
		})
	}
}

func TestFromConfigMapData_HeaderSecretName(t *testing.T) {
	p, err := FromConfigMapData(map[string]string{
		"type":               "otlp",
		"endpoint":           "otel:4318",
		"header_secret_name": "Authorization",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.HeaderName != "Authorization" {
		t.Errorf("HeaderName=%q want Authorization", p.HeaderName)
	}
}

func TestToConfigMapData_OTLPIncludesInsecureFalse(t *testing.T) {
	// Round-trip invariant: the operator's bundle reconciler renders
	// insecure="false" for plain OTLP so the agent sees a stable key
	// set regardless of the upstream ExporterConfig's zero-value bool.
	out := ToConfigMapData(&Payload{Type: TypeOTLP, Endpoint: "otel:4318"})
	if out["insecure"] != "false" {
		t.Errorf("insecure=%q want false for OTLP", out["insecure"])
	}
}

func TestToConfigMapData_OmitsEmptyFields(t *testing.T) {
	out := ToConfigMapData(&Payload{Type: TypeJaeger, Endpoint: "jaeger:14268"})
	if _, ok := out["protocol"]; ok {
		t.Errorf("protocol should be absent for Jaeger: %+v", out)
	}
	if _, ok := out["site"]; ok {
		t.Errorf("site should be absent for Jaeger: %+v", out)
	}
}

func TestConfigMapRoundTrip(t *testing.T) {
	original := &Payload{
		Type:     TypeOTLP,
		Endpoint: "otel:4318",
		Protocol: "grpc",
		Insecure: true,
		Sample:   0.25,
		Headers: map[string]string{
			"X-Env":    "prod",
			"X-Tenant": "team-a",
		},
	}
	rendered := ToConfigMapData(original)
	parsed, err := FromConfigMapData(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original.Headers, parsed.Headers) {
		t.Errorf("headers round-trip: %+v vs %+v", original.Headers, parsed.Headers)
	}
	if parsed.Type != original.Type || parsed.Protocol != original.Protocol {
		t.Errorf("type/protocol round-trip: %+v vs %+v", original, parsed)
	}
	if parsed.Sample != original.Sample {
		t.Errorf("sample round-trip: %v vs %v", original.Sample, parsed.Sample)
	}
}

func TestFromYAML_Minimal(t *testing.T) {
	p, err := FromYAML([]byte(`
type: otlp
endpoint: otel:4318
protocol: http
insecure: true
`))
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}
	if p.Type != TypeOTLP || !p.Insecure {
		t.Errorf("parsed wrong: %+v", p)
	}
}

func TestFromYAML_MissingTypeRejected(t *testing.T) {
	_, err := FromYAML([]byte("endpoint: otel:4318\n"))
	if err == nil {
		t.Fatal("expected error for missing type")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Errorf("error does not mention type: %v", err)
	}
}

func TestFromYAML_SampleOutOfRangeRejected(t *testing.T) {
	_, err := FromYAML([]byte("type: otlp\nsample: 1.5\n"))
	if err == nil {
		t.Fatal("expected error for sample > 1")
	}
}

func TestYAMLRoundTrip(t *testing.T) {
	original := &Payload{
		Type:     TypeOTLP,
		Endpoint: "otel:4318",
		Protocol: "http",
		Insecure: true,
		Sample:   0.5,
		Headers:  map[string]string{"X-Env": "prod"},
	}
	raw, err := ToYAML(original)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := FromYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original.Headers, parsed.Headers) {
		t.Errorf("headers round-trip: %+v vs %+v", original, parsed)
	}
	if parsed.Type != original.Type || parsed.Sample != original.Sample {
		t.Errorf("round-trip mismatch: %+v vs %+v", original, parsed)
	}
}

func TestToYAML_NilPayloadErrors(t *testing.T) {
	if _, err := ToYAML(nil); err == nil {
		t.Fatal("expected error on nil")
	}
}

// TestVersion_FromConfigMapData covers the bundle-versioning contract:
// empty version is legacy-OK (operators upgrading in place may write
// pre-versioning bundles), CurrentVersion is OK, anything else is a
// hard error so an older agent never silently misreads a newer schema.
func TestVersion_FromConfigMapData(t *testing.T) {
	cases := []struct {
		name    string
		version string
		wantErr bool
	}{
		{"LegacyEmptyAccepted", "", false},
		{"CurrentVersionAccepted", CurrentVersion, false},
		{"UnknownVersionRejected", "v999", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := map[string]string{"type": "otlp", "endpoint": "x:4318"}
			if tc.version != "" {
				data["version"] = tc.version
			}
			p, err := FromConfigMapData(data)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for version=%q", tc.version)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Version != tc.version {
				t.Errorf("Version round-trip: got %q, want %q", p.Version, tc.version)
			}
		})
	}
}

// TestVersion_FromYAML mirrors TestVersion_FromConfigMapData for the
// YAML path used by the CLI's --exporter-from-file.
func TestVersion_FromYAML(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"LegacyEmptyAccepted", "type: otlp\nendpoint: x:4318\n", false},
		{"CurrentVersionAccepted", "version: " + CurrentVersion + "\ntype: otlp\nendpoint: x:4318\n", false},
		{"UnknownVersionRejected", "version: v999\ntype: otlp\nendpoint: x:4318\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromYAML([]byte(tc.yaml))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for: %s", tc.yaml)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVersion_WritersAlwaysStampCurrent covers the producer side:
// regardless of what a Payload's in-memory Version field carries,
// ToConfigMapData and ToYAML always stamp CurrentVersion. This
// prevents an out-of-band Payload (constructed by a misconfigured
// test or stale cache) from leaking a stale version onto the wire.
func TestVersion_WritersAlwaysStampCurrent(t *testing.T) {
	p := &Payload{Version: "v0-old", Type: TypeOTLP, Endpoint: "x:4318"}

	data := ToConfigMapData(p)
	if data["version"] != CurrentVersion {
		t.Errorf("ToConfigMapData version = %q, want %q", data["version"], CurrentVersion)
	}

	raw, err := ToYAML(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := FromYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != CurrentVersion {
		t.Errorf("ToYAML/FromYAML version = %q, want %q", parsed.Version, CurrentVersion)
	}
}
