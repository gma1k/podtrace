package workloadmetrics

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func TestAShippedCopyOfAKernelCountedEventIsNotCountedTwice(t *testing.T) {
	sink, reg := kernelSink(t)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventTCPSend, 0, kernelagg.BucketIndex(250_000), 1, 250_000, 1500),
	})
	sink.record(&events.Event{
		Type: events.EventTCPSend, CgroupID: kernelTestCgroup, LatencyNS: 250_000,
		Bytes: 1500, KernelAggregated: true,
	}, checkoutBase)

	metrics := gather(t, reg, "podtrace_workload_network_bytes_total")
	if len(metrics) != 1 || metrics[0].GetCounter().GetValue() != 1500 {
		t.Errorf("network_bytes_total = %v, want 1500 for one 1500-byte send.\n\n"+
			"While a PodTrace is active the kernel both aggregates an event and ships it. "+
			"The drained row already counts it, so counting the shipped copy as well "+
			"doubled every counter the plane exports.", metrics)
	}
}

func TestAKernelCountedResponseStillFeedsTheSemanticConventionFamilies(t *testing.T) {
	clock := time.Now()
	sink, reg := fullSurfaceSink(t, true, &clock)
	sink.record(&events.Event{
		Type: events.EventHTTPResp, CgroupID: kernelTestCgroup, LatencyNS: 4_000_000,
		Error: 200, KernelAggregated: true,
	}, checkoutBase)

	if got := len(gather(t, reg, "http_server_request_duration_seconds")); got != 1 {
		t.Errorf("got %d semantic-convention series, want 1: the kernel map carries no "+
			"method or status code, so these histograms can only come from the event", got)
	}
	if got := len(gather(t, reg, "podtrace_workload_l7_requests_total")); got != 0 {
		t.Errorf("got %d l7_requests_total series from the event path; the drained row owns "+
			"that counter", got)
	}
}

func TestWithoutKernelIngestionAFlaggedEventIsStillCounted(t *testing.T) {
	sink, reg := eventSink(t)
	sink.record(&events.Event{
		Type: events.EventTCPSend, CgroupID: kernelTestCgroup, LatencyNS: 250_000,
		Bytes: 1500, KernelAggregated: true,
	}, checkoutBase)
	if got := gather(t, reg, "podtrace_workload_network_bytes_total"); len(got) != 1 {
		t.Errorf("a sink that does not ingest kernel rows dropped a flagged event; nothing " +
			"else would count it")
	}
}
