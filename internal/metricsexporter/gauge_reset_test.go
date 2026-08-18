package metricsexporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/events"
)

func TestResetLatestGauges_ClearsStaleSeries(t *testing.T) {
	ResetLatestGauges()

	ExportDNSMetricWithContext(&events.Event{Type: events.EventDNS, LatencyNS: 1_000_000}, "ns-reset")
	ExportTLSMetricWithContext(&events.Event{Type: events.EventTLSHandshake, LatencyNS: 2_000_000}, "ns-reset")

	if n := testutil.CollectAndCount(dnsGauge); n == 0 {
		t.Fatal("expected a dns gauge series after export")
	}
	if n := testutil.CollectAndCount(tlsGauge); n == 0 {
		t.Fatal("expected a tls gauge series after export")
	}

	ResetLatestGauges()

	if n := testutil.CollectAndCount(dnsGauge); n != 0 {
		t.Fatalf("ResetLatestGauges left %d dns gauge series, want 0", n)
	}
	if n := testutil.CollectAndCount(tlsGauge); n != 0 {
		t.Fatalf("ResetLatestGauges left %d tls gauge series, want 0", n)
	}
}
