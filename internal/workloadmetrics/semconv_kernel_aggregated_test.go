package workloadmetrics

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

func kernelSemconvSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:    true,
		KernelAggregation:   true,
		SemanticConventions: true,
		Lookup:              kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func TestAKernelCountedResponseFeedsTheConventionsWithoutBeingCountedAgain(t *testing.T) {
	sink, reg := kernelSemconvSink(t)

	served := &events.Event{
		Type: events.EventHTTPResp, CgroupID: kernelTestCgroup, LatencyNS: 3_000_000,
		TCPState:   events.HTTPRoleKnownBit | events.HTTPRoleServerBit,
		HTTPMethod: "GET", Details: "200", KernelAggregated: true,
	}
	query := &events.Event{
		Type: events.EventDBQuery, CgroupID: kernelTestCgroup, LatencyNS: 1_000_000,
		Target: "insert into orders values (42)", KernelAggregated: true,
	}
	if err := sink.Export(context.Background(), []*events.Event{served, query}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	httpSeries := gather(t, reg, semconvHTTPDuration)
	if len(httpSeries) != 1 {
		t.Fatalf("got %d %s series, want 1: with the bypass armed these events are the only "+
			"source of the method and status code", len(httpSeries), semconvHTTPDuration)
	}
	if got := labelsOf(httpSeries[0]); got["http_request_method"] != "GET" || got["http_response_status_code"] != "200" {
		t.Errorf("http labels = %v", got)
	}
	dbSeries := gather(t, reg, semconvDBDuration)
	if len(dbSeries) != 1 || labelsOf(dbSeries[0])["db_operation_name"] != "INSERT" {
		t.Fatalf("db series = %v, want one with db_operation_name INSERT", dbSeries)
	}

	for _, family := range []string{"podtrace_workload_l7_requests_total", "podtrace_workload_l7_request_duration_seconds"} {
		for _, m := range gather(t, reg, family) {
			if c := m.GetCounter(); c != nil && c.GetValue() != 0 {
				t.Errorf("%s counted %v from events the kernel already counted", family, c.GetValue())
			}
			if h := m.GetHistogram(); h != nil && h.GetSampleCount() != 0 {
				t.Errorf("%s observed %d samples from events the kernel already counted", family, h.GetSampleCount())
			}
		}
	}
}

func TestAKernelCountedClientResponseStaysOutOfTheServerConventions(t *testing.T) {
	sink, reg := kernelSemconvSink(t)

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventHTTPResp, CgroupID: kernelTestCgroup, LatencyNS: 3_000_000,
		TCPState:   events.HTTPRoleKnownBit,
		HTTPMethod: "GET", Details: "200", KernelAggregated: true,
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := gather(t, reg, semconvHTTPDuration); len(got) != 0 {
		t.Errorf("a response to a call the workload made produced %d server-duration series", len(got))
	}
}
