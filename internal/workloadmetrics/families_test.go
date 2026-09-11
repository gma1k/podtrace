package workloadmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func TestKernelFedFamiliesAreVisibleToTheInspectionRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		typ    events.EventType
		family string
	}{
		{"l7 latency", events.EventHTTPResp, "podtrace_workload_l7_request_duration_seconds"},
		{"connection acquire", events.EventDBAcquire, "podtrace_workload_db_connection_acquire_seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, _ := kernelSink(t)
			row := kernelRow(tc.typ, 0, kernelagg.BucketIndex(300_000_000), 5, 1_500_000_000, 0)
			if !sink.ingestKernelRow(&row) {
				t.Fatal("kernel row was not ingested")
			}

			got := sink.CollectFamilies([]string{tc.family})
			if len(got[tc.family]) == 0 {
				t.Errorf("the rules see no series for %s under kernel aggregation.\n\n"+
					"collectorFor resolves a family to a registered vec, but when the "+
					"kernel aggregates, that vec is deliberately not registered and holds "+
					"nothing: the series live in kernelHistograms. A rule reading this "+
					"family then evaluates an empty window and reports every workload "+
					"healthy forever, with no error anywhere to say the signal is gone.",
					tc.family)
			}
		})
	}
}

func TestOneKernelFamilyDoesNotLeakAnothersSeries(t *testing.T) {
	sink, _ := kernelSink(t)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventHTTPResp, 0, kernelagg.BucketIndex(200_000_000), 3, 600_000_000, 0),
		kernelRow(events.EventDBAcquire, 0, kernelagg.BucketIndex(400_000_000), 2, 800_000_000, 0),
	})

	got := sink.CollectFamilies([]string{"podtrace_workload_db_connection_acquire_seconds"})
	series := got["podtrace_workload_db_connection_acquire_seconds"]
	if len(series) != 1 {
		t.Fatalf("got %d series, want 1", len(series))
	}
	if c := series[0].GetHistogram().GetSampleCount(); c != 2 {
		t.Errorf("count = %d, want 2; draining the whole kernel collector would fold "+
			"every other family's observations into whichever name was asked for", c)
	}
}

func TestKernelFamilyCollectorDescribesOnlyItsOwnFamily(t *testing.T) {
	sink, _ := kernelSink(t)

	c, ok := sink.collectorFor("podtrace_workload_db_connection_acquire_seconds")
	if !ok {
		t.Fatal("no collector resolved for a kernel-fed family")
	}

	ch := make(chan *prometheus.Desc, 8)
	c.Describe(ch)
	close(ch)

	var descs []string
	for d := range ch {
		descs = append(descs, d.String())
	}
	if len(descs) != 1 {
		t.Fatalf("Describe emitted %d descriptors, want exactly 1: %v", len(descs), descs)
	}
	if !strings.Contains(descs[0], "db_connection_acquire_seconds") {
		t.Errorf("Describe emitted %q, which is not this collector's family", descs[0])
	}
}

func TestKernelFamilyCollectorDescribesNothingForAnUnknownFamily(t *testing.T) {
	sink, _ := kernelSink(t)

	c := kernelFamilyCollector{k: sink.kernelHist, family: "not_a_family"}
	ch := make(chan *prometheus.Desc, 4)
	c.Describe(ch)
	close(ch)

	if n := len(ch); n != 0 {
		t.Errorf("Describe emitted %d descriptors for an unknown family; a nil Desc "+
			"reaching the registry panics the whole scrape", n)
	}
}
