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

// TestTargetNamespaces_ConfigMapTriState pins the wire contract for
// allowlist field: agents have to distinguish "selector
// not set"
func TestTargetNamespaces_ConfigMapTriState(t *testing.T) {
	cases := []struct {
		name      string
		input     *Payload
		wantKey   bool
		wantValue string
		wantField []string
		fieldIsNil bool
	}{
		{
			name:      "NilFieldOmitsKey",
			input:     &Payload{Type: TypeOTLP, Endpoint: "x:4318", TargetNamespaces: nil},
			wantKey:   false,
			fieldIsNil: true,
		},
		{
			name:      "EmptySliceWritesEmptyValue",
			input:     &Payload{Type: TypeOTLP, Endpoint: "x:4318", TargetNamespaces: []string{}},
			wantKey:   true,
			wantValue: "",
			wantField: []string{},
		},
		{
			name:      "PopulatedSliceWritesCommaJoined",
			input:     &Payload{Type: TypeOTLP, Endpoint: "x:4318", TargetNamespaces: []string{"team-b", "team-a", "prod"}},
			wantKey:   true,
			wantValue: "prod,team-a,team-b",
			wantField: []string{"prod", "team-a", "team-b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := ToConfigMapData(tc.input)
			val, ok := data["target_namespaces"]
			if ok != tc.wantKey {
				t.Fatalf("target_namespaces key presence = %v, want %v", ok, tc.wantKey)
			}
			if ok && val != tc.wantValue {
				t.Errorf("target_namespaces value = %q, want %q", val, tc.wantValue)
			}
			parsed, err := FromConfigMapData(data)
			if err != nil {
				t.Fatalf("parse back: %v", err)
			}
			if tc.fieldIsNil {
				if parsed.TargetNamespaces != nil {
					t.Errorf("expected nil after round-trip, got %v", parsed.TargetNamespaces)
				}
				return
			}
			if parsed.TargetNamespaces == nil {
				t.Fatal("expected non-nil slice after round-trip, got nil")
			}
			if !reflect.DeepEqual(parsed.TargetNamespaces, tc.wantField) {
				t.Errorf("round-trip slice = %v, want %v", parsed.TargetNamespaces, tc.wantField)
			}
		})
	}
}

func TestTargetNamespaces_AgentRejectV1BundleAfterV2Migration(t *testing.T) {
	_, err := FromConfigMapData(map[string]string{
		"version":           "v3-future",
		"type":              "otlp",
		"endpoint":          "x:4318",
		"target_namespaces": "team-a",
	})
	if err == nil {
		t.Fatal("FromConfigMapData should reject unknown future version")
	}
	if !contains(err.Error(), "v3-future") {
		t.Errorf("error %q should name the unknown version", err.Error())
	}
	if !contains(err.Error(), CurrentVersion) {
		t.Errorf("error %q should name the current version", err.Error())
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// TestFilters_RoundTrip locks the wire contract for the filters field:
// empty in / empty out, populated list goes through sorted-dedup-CSV.
func TestFilters_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   []FilterCategory
		want []FilterCategory
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty", in: []FilterCategory{}, want: nil},
		{
			name: "sorted",
			in:   []FilterCategory{FilterNet, FilterDNS},
			want: []FilterCategory{FilterDNS, FilterNet},
		},
		{
			name: "dedupe",
			in:   []FilterCategory{FilterFS, FilterFS, FilterDNS},
			want: []FilterCategory{FilterDNS, FilterFS},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Payload{Type: TypeOTLP, Endpoint: "x:4318", Filters: tc.in}
			data := ToConfigMapData(p)
			parsed, err := FromConfigMapData(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(parsed.Filters, tc.want) {
				t.Errorf("filters round-trip = %v, want %v", parsed.Filters, tc.want)
			}
		})
	}
}

// TestThresholds_TriStateRoundTrip pins key-presence semantics so
// "unset threshold" survives round-trip distinct from "threshold=0".
func TestThresholds_TriStateRoundTrip(t *testing.T) {
	five := int32(5)
	zero := int32(0)
	cases := []struct {
		name string
		in   *Thresholds
	}{
		{name: "nil", in: nil},
		{name: "only_error_rate", in: &Thresholds{ErrorRatePercent: &five}},
		{name: "zero_is_distinct_from_unset", in: &Thresholds{FSSlowMs: &zero}},
		{name: "all", in: &Thresholds{ErrorRatePercent: &five, RTTSpikeMs: &five, FSSlowMs: &five}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Payload{Type: TypeOTLP, Endpoint: "x:4318", Thresholds: tc.in}
			data := ToConfigMapData(p)
			parsed, err := FromConfigMapData(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if tc.in == nil {
				if parsed.Thresholds != nil {
					t.Fatalf("expected nil thresholds, got %+v", parsed.Thresholds)
				}
				return
			}
			if parsed.Thresholds == nil {
				t.Fatalf("expected non-nil thresholds")
			}
			if !int32PtrEq(parsed.Thresholds.ErrorRatePercent, tc.in.ErrorRatePercent) ||
				!int32PtrEq(parsed.Thresholds.RTTSpikeMs, tc.in.RTTSpikeMs) ||
				!int32PtrEq(parsed.Thresholds.FSSlowMs, tc.in.FSSlowMs) {
				t.Errorf("threshold round-trip mismatch:\ngot  %+v\nwant %+v", parsed.Thresholds, tc.in)
			}
		})
	}
}

func int32PtrEq(a, b *int32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// TestThresholds_NegativeRejected guards the wire format from being
// usable for sentinel-style negative values that downstream consumers
// would have to special-case.
func TestThresholds_NegativeRejected(t *testing.T) {
	_, err := FromConfigMapData(map[string]string{
		"type":                   "otlp",
		"endpoint":               "x:4318",
		"threshold_rtt_spike_ms": "-1",
	})
	if err == nil {
		t.Fatal("expected error for negative threshold_rtt_spike_ms")
	}
}

// TestPolicyHash_StableAcrossEquivalentPolicies pins the
// "different exporters, same policy ⇒ same hash" property. Users diff
// status.policy.hash against agent-side PodTraceNodeStatus.PolicyHash;
// if endpoint or credentials affected the hash the diff would drift.
func TestPolicyHash_StableAcrossEquivalentPolicies(t *testing.T) {
	five := int32(5)
	a := &Payload{
		Type: TypeOTLP, Endpoint: "a:4318",
		Sample:     0.5,
		Filters:    []FilterCategory{FilterDNS, FilterNet},
		Thresholds: &Thresholds{FSSlowMs: &five},
	}
	b := &Payload{
		Type: TypeJaeger, Endpoint: "b:14268",
		Sample:     0.5,
		Filters:    []FilterCategory{FilterNet, FilterDNS}, // unsorted
		Thresholds: &Thresholds{FSSlowMs: &five},
	}
	if PolicyHash(a) != PolicyHash(b) {
		t.Errorf("equivalent policies produced different hashes:\nA=%s\nB=%s", PolicyHash(a), PolicyHash(b))
	}
}

// TestPolicyHash_ChangesWhenAnyPolicyFieldChanges guards against the
// hash silently ignoring a policy field.
func TestPolicyHash_ChangesWhenAnyPolicyFieldChanges(t *testing.T) {
	five := int32(5)
	ten := int32(10)
	base := &Payload{
		Type: TypeOTLP, Endpoint: "x:4318",
		Sample:     0.5,
		Filters:    []FilterCategory{FilterDNS},
		Thresholds: &Thresholds{FSSlowMs: &five},
	}
	mutations := map[string]func(*Payload){
		"sample_changed":     func(p *Payload) { p.Sample = 0.25 },
		"filter_added":       func(p *Payload) { p.Filters = append(p.Filters, FilterNet) },
		"threshold_changed":  func(p *Payload) { p.Thresholds.FSSlowMs = &ten },
		"threshold_removed":  func(p *Payload) { p.Thresholds = nil },
	}
	baseHash := PolicyHash(base)
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := *base
			copyThresholds := *base.Thresholds
			copy.Thresholds = &copyThresholds
			copy.Filters = append([]FilterCategory(nil), base.Filters...)
			mutate(&copy)
			if PolicyHash(&copy) == baseHash {
				t.Errorf("hash unchanged after %s", name)
			}
		})
	}
}

// TestPolicyGeneration_RoundTrip pins the new policy_generation key.
func TestPolicyGeneration_RoundTrip(t *testing.T) {
	p := &Payload{Type: TypeOTLP, Endpoint: "x:4318", PolicyGeneration: 42}
	parsed, err := FromConfigMapData(ToConfigMapData(p))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.PolicyGeneration != 42 {
		t.Errorf("policy_generation round-trip = %d, want 42", parsed.PolicyGeneration)
	}
}
