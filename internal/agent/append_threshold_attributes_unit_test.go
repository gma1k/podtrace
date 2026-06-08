package agent

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func hasAttrKey(attrs []attribute.KeyValue, key string) bool {
	for _, a := range attrs {
		if string(a.Key) == key {
			return true
		}
	}
	return false
}

func TestAppendThresholdAttributes_NilThresholds(t *testing.T) {
	e := &sdkEventExporter{cr: CRKey{"ns", "cr"}}
	in := []attribute.KeyValue{}
	got := e.appendThresholdAttributes(in, &events.Event{Type: events.EventOpen})
	if len(got) != 0 {
		t.Errorf("nil thresholds should not append, got %v", got)
	}
}

func int32Ptr(v int32) *int32 { return &v }

func TestAppendThresholdAttributes_Branches(t *testing.T) {
	ms := int32(1)
	thresholdNs := uint64(ms) * uint64(config.NSPerMS)

	e := &sdkEventExporter{
		cr: CRKey{"ns", "cr"},
		thresholds: &PolicyThresholds{
			FSSlowMs:         int32Ptr(ms),
			RTTSpikeMs:       int32Ptr(ms),
			ErrorRatePercent: int32Ptr(50),
		},
	}

	fsAttrs := e.appendThresholdAttributes(nil, &events.Event{
		Type:      events.EventOpen,
		LatencyNS: thresholdNs + 1,
	})
	if !hasAttrKey(fsAttrs, "podtrace.threshold.fs_slow.tripped") {
		t.Errorf("expected fs_slow tripped attribute, got %v", fsAttrs)
	}

	rttAttrs := e.appendThresholdAttributes(nil, &events.Event{
		Type:      events.EventConnect,
		LatencyNS: thresholdNs + 1,
	})
	if !hasAttrKey(rttAttrs, "podtrace.threshold.rtt_spike.tripped") {
		t.Errorf("expected rtt_spike tripped attribute, got %v", rttAttrs)
	}

	errAttrs := e.appendThresholdAttributes(nil, &events.Event{
		Type:  events.EventOpen,
		Error: 1,
	})
	if !hasAttrKey(errAttrs, "podtrace.threshold.error_rate.observed") {
		t.Errorf("expected error_rate observed attribute, got %v", errAttrs)
	}

	noneAttrs := e.appendThresholdAttributes(nil, &events.Event{
		Type:      events.EventOpen,
		LatencyNS: 0,
	})
	if hasAttrKey(noneAttrs, "podtrace.threshold.fs_slow.tripped") {
		t.Errorf("did not expect fs_slow attribute below threshold, got %v", noneAttrs)
	}
}
