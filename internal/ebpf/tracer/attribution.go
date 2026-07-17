package tracer

import (
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/metricsexporter"
)

// Attribution sources reported to podtrace_attribution_total.
const (
	attributionSourceEventComm    = "event_comm"
	attributionSourceCorrelator   = "correlator"
	attributionSourceProcFallback = "proc_fallback"
	attributionSourceNone         = "none"
)

// attributeProcessName fills event.ProcessName for events that arrived
// without a kernel-captured comm, the cgroup_skb producers (DNS, QUIC),
// which cannot call bpf_get_current_comm — and reports where the name
// came from.
func (t *Tracer) attributeProcessName(event *events.Event) string {
	if event.ProcessName != "" {
		return attributionSourceEventComm
	}
	if !t.attributionCorrelatorDisabled {
		name, ok, reuseSuspected := t.attributionTable.Lookup(event.PID, event.CgroupID)
		if ok {
			event.ProcessName = name
			return attributionSourceCorrelator
		}
		if reuseSuspected {
			metricsexporter.RecordAttributionPidReuseSuspected()
		}
	}
	event.ProcessName = t.getProcessNameQuick(event.PID)
	if event.ProcessName != "" {
		return attributionSourceProcFallback
	}
	return attributionSourceNone
}

// recordAttributionOutcome feeds the attribution table and the metrics
// from one dispatched event.
func (t *Tracer) recordAttributionOutcome(event *events.Event, source string) {
	if source == attributionSourceEventComm && event.ProcessName != "" {
		t.attributionTable.Record(event.PID, event.CgroupID, event.ProcessName)
	}
	metricsexporter.RecordAttribution(source, attributionEventKind(event.Type))
}

// attributionEventKind buckets event types for the attribution metric:
// dns and quic are the cgroup_skb-sourced kinds the attribution work
// targets, everything else is the baseline.
func attributionEventKind(t events.EventType) string {
	switch t {
	case events.EventDNS, events.EventDNSQuery:
		return "dns"
	case events.EventHTTP3:
		return "quic"
	default:
		return "other"
	}
}
