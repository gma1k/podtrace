package bundle

import (
	"strings"
	"testing"
)

func TestSynthesizeSpansRoundTrips(t *testing.T) {
	data := ToConfigMapData(&Payload{Type: TypeOTLP, Endpoint: "c:4318", SynthesizeSpans: true})
	if data["synthesize_spans"] != "true" {
		t.Fatalf("synthesize_spans = %q, want true", data["synthesize_spans"])
	}

	out, err := FromConfigMapData(data)
	if err != nil {
		t.Fatalf("FromConfigMapData: %v", err)
	}
	if !out.SynthesizeSpans {
		t.Error("SynthesizeSpans did not survive the round trip; a session asked to mint spans " +
			"for context-less traffic would silently stop doing so")
	}
}

func TestSiteAndHeaderSecretNameRoundTrip(t *testing.T) {
	data := ToConfigMapData(&Payload{
		Type:       TypeDataDog,
		Endpoint:   "dd:4318",
		Site:       "datadoghq.eu",
		HeaderName: "authorization",
	})
	if data["site"] != "datadoghq.eu" {
		t.Errorf("site = %q, want datadoghq.eu", data["site"])
	}
	if data["header_secret_name"] != "authorization" {
		t.Errorf("header_secret_name = %q, want authorization", data["header_secret_name"])
	}

	out, err := FromConfigMapData(data)
	if err != nil {
		t.Fatalf("FromConfigMapData: %v", err)
	}
	if out.Site != "datadoghq.eu" || out.HeaderName != "authorization" {
		t.Errorf("round trip gave site=%q headerName=%q", out.Site, out.HeaderName)
	}
}

func TestEmptyFilterEntriesAreDroppedInBothDirections(t *testing.T) {
	out, err := FromConfigMapData(map[string]string{
		"version":  CurrentVersion,
		"type":     string(TypeOTLP),
		"endpoint": "c:4318",
		"filters":  "dns,,  ,net,",
	})
	if err != nil {
		t.Fatalf("FromConfigMapData: %v", err)
	}
	if len(out.Filters) != 2 {
		t.Errorf("parsed filters %v, want just dns and net; blank entries between commas are "+
			"not categories and would reach the agent as an empty probe group", out.Filters)
	}

	data := ToConfigMapData(&Payload{
		Type: TypeOTLP, Endpoint: "c:4318",
		Filters: []FilterCategory{FilterDNS, "", FilterNet},
	})
	if data["filters"] != "dns,net" {
		t.Errorf("rendered filters = %q, want dns,net", data["filters"])
	}
}

func TestMalformedPolicyGenerationIsRejected(t *testing.T) {
	_, err := FromConfigMapData(map[string]string{
		"version":           CurrentVersion,
		"type":              string(TypeOTLP),
		"endpoint":          "c:4318",
		"policy_generation": "seventeen",
	})
	if err == nil {
		t.Fatal("a non-numeric policy_generation was accepted; agents compare it to assert " +
			"policy propagation, so a garbage value would make them report a phantom mismatch")
	}
	if !strings.Contains(err.Error(), "policy_generation") {
		t.Errorf("error %q does not name the field", err)
	}
}

func TestMalformedThresholdIsRejected(t *testing.T) {
	for _, key := range []string{
		"threshold_error_rate_percent",
		"threshold_rtt_spike_ms",
		"threshold_fs_slow_ms",
	} {
		data := map[string]string{
			"version":  CurrentVersion,
			"type":     string(TypeOTLP),
			"endpoint": "c:4318",
			key:        "quite-slow",
		}
		if _, err := FromConfigMapData(data); err == nil {
			t.Errorf("%s accepted a non-numeric value", key)
		}
	}
}

func TestNilPayloadIsInertEverywhere(t *testing.T) {
	if got := ToConfigMapData(nil); got != nil {
		t.Errorf("ToConfigMapData(nil) = %v, want nil", got)
	}
	if got := PolicyHash(nil); got != "" {
		t.Errorf("PolicyHash(nil) = %q, want empty", got)
	}
	if _, err := ToYAML(nil); err == nil {
		t.Error("ToYAML(nil) returned no error")
	}
}

func TestUnparseableYAMLIsReported(t *testing.T) {
	_, err := FromYAML([]byte("type: otlp\n  endpoint: [unclosed\n"))
	if err == nil {
		t.Fatal("malformed YAML was accepted; the CLI reads this file from a mounted ConfigMap " +
			"and a silent zero Payload would trace with no exporter at all")
	}
	if !strings.Contains(err.Error(), "parse YAML") {
		t.Errorf("error %q does not report a YAML parse failure", err)
	}
}
