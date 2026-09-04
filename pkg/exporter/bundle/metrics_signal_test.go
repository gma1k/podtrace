package bundle

import (
	"strings"
	"testing"
	"time"
)

func TestMetricsFlagRoundTripsThroughTheConfigMap(t *testing.T) {
	in := &Payload{
		Type:            TypeOTLP,
		Endpoint:        "collector:4318",
		Metrics:         true,
		MetricsInterval: 90 * time.Second,
	}

	data := ToConfigMapData(in)
	if data["metrics"] != "true" {
		t.Errorf("metrics key = %q, want true", data["metrics"])
	}
	if data["metrics_interval_seconds"] != "90" {
		t.Errorf("metrics_interval_seconds = %q, want 90", data["metrics_interval_seconds"])
	}

	out, err := FromConfigMapData(data)
	if err != nil {
		t.Fatalf("FromConfigMapData: %v", err)
	}
	if !out.Metrics {
		t.Error("Metrics did not survive the round trip")
	}
	if out.MetricsInterval != 90*time.Second {
		t.Errorf("MetricsInterval = %v, want 90s", out.MetricsInterval)
	}
}

func TestMetricsKeysAbsentWhenNotRequested(t *testing.T) {
	data := ToConfigMapData(&Payload{Type: TypeOTLP, Endpoint: "collector:4318"})
	for _, key := range []string{"metrics", "metrics_interval_seconds"} {
		if _, present := data[key]; present {
			t.Errorf("key %q rendered without being requested; an absent key is how the agent "+
				"reads the default", key)
		}
	}
}

func TestZeroIntervalMeansTheAgentDefault(t *testing.T) {
	data := ToConfigMapData(&Payload{Type: TypeOTLP, Endpoint: "c:4318", Metrics: true})
	if _, present := data["metrics_interval_seconds"]; present {
		t.Error("a zero interval rendered a key; the agent's default must stay in one place")
	}
}

func TestMetricsRoundTripsThroughYAML(t *testing.T) {
	raw, err := ToYAML(&Payload{
		Type:            TypeOTLP,
		Endpoint:        "collector:4318",
		Metrics:         true,
		MetricsInterval: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("ToYAML: %v", err)
	}
	out, err := FromYAML(raw)
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}
	if !out.Metrics || out.MetricsInterval != 2*time.Minute {
		t.Errorf("YAML round trip gave metrics=%v interval=%v, want true/2m0s from %q",
			out.Metrics, out.MetricsInterval, raw)
	}
}

func TestMetricsOnANonOTLPExporterIsRejected(t *testing.T) {
	for _, typ := range []Type{TypeJaeger, TypeZipkin, TypeSplunk, TypeDataDog} {
		_, err := FromConfigMapData(map[string]string{
			"version":  CurrentVersion,
			"type":     string(typ),
			"endpoint": "somewhere:4318",
			"metrics":  "true",
		})
		if err == nil {
			t.Errorf("type %q accepted a metrics request; no other backend in this set speaks "+
				"OTLP metrics, so accepting it would promise an export that never happens", typ)
			continue
		}
		if !strings.Contains(err.Error(), "metrics export requires type") {
			t.Errorf("type %q rejected with %q, want a message naming the constraint", typ, err)
		}
	}
}

func TestMalformedMetricsIntervalIsRejected(t *testing.T) {
	for _, raw := range []string{"soon", "-30", "1.5"} {
		if _, err := FromConfigMapData(map[string]string{
			"version":                  CurrentVersion,
			"type":                     string(TypeOTLP),
			"endpoint":                 "collector:4318",
			"metrics":                  "true",
			"metrics_interval_seconds": raw,
		}); err == nil {
			t.Errorf("metrics_interval_seconds %q was accepted", raw)
		}
	}
}

func TestNegativeMetricsIntervalIsRejectedOnThePayload(t *testing.T) {
	if _, err := FromYAML([]byte("type: otlp\nendpoint: c:4318\nmetrics: true\nmetricsInterval: -5s\n")); err == nil {
		t.Error("a negative metricsInterval was accepted")
	}
}

func TestMetricsIsNotPartOfThePolicyHash(t *testing.T) {
	withMetrics := &Payload{Type: TypeOTLP, Endpoint: "c:4318", Metrics: true, MetricsInterval: time.Minute}
	without := &Payload{Type: TypeOTLP, Endpoint: "c:4318"}
	if PolicyHash(withMetrics) != PolicyHash(without) {
		t.Error("the metrics flag changed the policy hash; the hash covers the tracing policy " +
			"agents assert propagation on, and a metrics-only edit must not look like a policy " +
			"change to every node")
	}
}
