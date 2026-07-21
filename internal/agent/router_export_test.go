package agent

import (
	"context"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestRouter_Export_EmptyBatchIsNoop(t *testing.T) {
	exp := &recExp{name: "x"}
	r := NewRouter(nil)
	r.Publish([]CRRule{
		mkRule("ns", "n", []uint64{1}, []events.EventType{events.EventDNS}, exp),
	})

	if err := r.Export(context.Background(), nil); err != nil {
		t.Fatalf("Export(nil batch): %v", err)
	}
	if err := r.Export(context.Background(), []*events.Event{}); err != nil {
		t.Fatalf("Export(empty batch): %v", err)
	}
	if exp.count() != 0 {
		t.Errorf("empty batch delivered %d events, want 0", exp.count())
	}
}

func TestRouter_Export_NilEventSkipped(t *testing.T) {
	exp := &recExp{name: "x"}
	r := NewRouter(nil)
	r.Publish([]CRRule{
		mkRule("ns", "n", []uint64{1}, []events.EventType{events.EventDNS}, exp),
	})

	batch := []*events.Event{
		{CgroupID: 1, Type: events.EventDNS},
		nil,
		{CgroupID: 1, Type: events.EventDNS},
	}
	if err := r.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if exp.count() != 2 {
		t.Errorf("delivered %d events, want 2 (nil skipped)", exp.count())
	}
}

func TestRouter_Export_NoRulesIsNoop(t *testing.T) {
	r := NewRouter(nil)
	if err := r.Export(context.Background(), []*events.Event{{CgroupID: 1, Type: events.EventDNS}}); err != nil {
		t.Fatalf("Export with no rules: %v", err)
	}
}
