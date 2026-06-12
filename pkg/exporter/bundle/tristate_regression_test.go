package bundle

import (
	"reflect"
	"testing"
)

// TestYAML_TargetNamespacesTriState: omitempty collapsed []string{}
// ("matched nothing — trace nothing") into nil ("legacy own-namespace
// fallback") through the YAML round-trip, so a session whose namespace
// selector matched no namespaces traced pods it was told to exclude.
func TestYAML_TargetNamespacesTriState(t *testing.T) {
	cases := []struct {
		name string
		in   []string
	}{
		{"nil means legacy fallback", nil},
		{"empty means match nothing", []string{}},
		{"populated allowlist", []string{"a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := ToYAML(&Payload{Type: TypeOTLP, Endpoint: "otel:4318", TargetNamespaces: c.in})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := FromYAML(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed.TargetNamespaces, c.in) {
				t.Errorf("round-trip: %#v -> %#v (YAML:\n%s)", c.in, parsed.TargetNamespaces, raw)
			}
		})
	}
}

// TestSampleZero_Representable: every consumer used to guard Sample > 0,
// so a user explicitly asking for 0% sampling silently got the default
// (100%). An explicit 0 must survive both wire formats and stay distinct
// from "not configured".
func TestSampleZero_Representable(t *testing.T) {
	zero := 0.0

	t.Run("configmap", func(t *testing.T) {
		data := ToConfigMapData(&Payload{Type: TypeOTLP, Endpoint: "e", Sample: &zero})
		if data["sample_percent"] != "0" {
			t.Fatalf("sample_percent = %q, want explicit \"0\"", data["sample_percent"])
		}
		parsed, err := FromConfigMapData(data)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Sample == nil || *parsed.Sample != 0 {
			t.Errorf("parsed Sample = %v, want explicit 0", parsed.Sample)
		}

		unset := ToConfigMapData(&Payload{Type: TypeOTLP, Endpoint: "e"})
		if _, ok := unset["sample_percent"]; ok {
			t.Error("unset Sample must not write sample_percent")
		}
	})

	t.Run("yaml", func(t *testing.T) {
		raw, err := ToYAML(&Payload{Type: TypeOTLP, Endpoint: "e", Sample: &zero})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := FromYAML(raw)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Sample == nil || *parsed.Sample != 0 {
			t.Errorf("parsed Sample = %v, want explicit 0", parsed.Sample)
		}
	})

	t.Run("hash distinguishes zero from unset", func(t *testing.T) {
		withZero := PolicyHash(&Payload{Type: TypeOTLP, Endpoint: "e", Sample: &zero})
		unset := PolicyHash(&Payload{Type: TypeOTLP, Endpoint: "e"})
		if withZero == unset {
			t.Error("policy hash must distinguish explicit 0%% from unset")
		}
	})
}
