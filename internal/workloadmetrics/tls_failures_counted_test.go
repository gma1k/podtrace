package workloadmetrics

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func tlsHandshakeCount(t *testing.T, reg *prometheus.Registry) uint64 {
	t.Helper()
	var n uint64
	for _, m := range gather(t, reg, "podtrace_workload_tls_handshake_duration_seconds") {
		n += m.GetHistogram().GetSampleCount()
	}
	return n
}

func TestAFailedHandshakeRowIsAHandshakeAndATLSError(t *testing.T) {
	sink, reg := kernelSink(t)
	bucket := kernelagg.BucketIndex(4_000_000)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventTLSHandshake, 0, bucket, 18, 18*4_000_000, 0),
		kernelRow(events.EventTLSHandshake, 1<<6, bucket, 2, 2*4_000_000, 0),
	})
	if got := tlsHandshakeCount(t, reg); got != 20 {
		t.Errorf("%d handshakes, want 20: the rule divides by every handshake, failed ones included", got)
	}
	if got := counterByLabel(t, reg, "podtrace_workload_errors_total", "kind"); got["tls"] != 2 {
		t.Errorf("tls errors %v, want the 2 failed handshakes", got)
	}
}

func TestAFailedHandshakeEventIsAHandshakeAndATLSError(t *testing.T) {
	sink, reg := dnsSink(t, false, true)
	batch := []*events.Event{
		{Type: events.EventTLSHandshake, LatencyNS: 3_000_000, K8s: enriched()},
		{Type: events.EventTLSHandshake, LatencyNS: 3_000_000, Error: -1, K8s: enriched()},
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if got := tlsHandshakeCount(t, reg); got != 2 {
		t.Errorf("%d handshakes, want 2", got)
	}
	if got := counterByLabel(t, reg, "podtrace_workload_errors_total", "kind"); got["tls"] != 1 {
		t.Errorf("tls errors %v, want the failed handshake", got)
	}
}
