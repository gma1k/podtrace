package workloadmetrics

import (
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func fullSurfaceSink(t *testing.T, kernel bool, clock *time.Time) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:    true,
		KernelAggregation:   kernel,
		SemanticConventions: true,
		Lookup:              kernelTestLookup,
		ResolvePeer: func(string, uint16) (PeerIdentity, bool) {
			return PeerIdentity{Service: "payments", Namespace: "billing"}, true
		},
		Now: func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func feedEveryEventType(t *testing.T, sink *Sink) {
	t.Helper()
	var evs []*events.Event
	var rows []kernelagg.Row
	for typ := range allEventTypes {
		evs = append(evs, &events.Event{
			Type: typ, CgroupID: kernelTestCgroup, LatencyNS: 1_000_000, Bytes: 64,
			Error: 1, TCPState: 1, Target: "postgresql-pool", Details: "SELECT 1",
			PeerDstIP: "10.244.1.7", PeerDstPort: 8080,
		})
		for _, bucket := range []uint16{kernelagg.BucketIndex(1_000_000), kernelagg.BucketNone} {
			row := kernelPeerRow(typ, 0, bucket, 1, 1_000_000, 64)
			rows = append(rows, row)
		}
	}
	exportAll(t, sink, evs...)
	sink.IngestKernel(rows)
}

func familiesLabelling(t *testing.T, reg *prometheus.Registry, value string) []string {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var out []string
	for _, f := range families {
		for _, m := range f.GetMetric() {
			found := false
			for _, l := range m.GetLabel() {
				if l.GetValue() == value {
					found = true
					break
				}
			}
			if found {
				out = append(out, f.GetName())
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestNothingOfADepartedWorkloadOutlivesTheReaper(t *testing.T) {
	for _, kernel := range []bool{false, true} {
		name := "event path"
		if kernel {
			name = "kernel aggregation"
		}
		t.Run(name, func(t *testing.T) {
			clock := time.Now()
			sink, reg := fullSurfaceSink(t, kernel, &clock)
			feedEveryEventType(t, sink)

			before := familiesLabelling(t, reg, "checkout")
			if len(before) < 10 {
				t.Fatalf("only %d families carried the workload before reaping (%v); the "+
					"fixture is not exercising the surface", len(before), before)
			}

			clock = clock.Add(20 * time.Minute)
			sink.Reap(15 * time.Minute)

			if left := familiesLabelling(t, reg, "checkout"); len(left) != 0 {
				t.Errorf("after the workload was idle past the TTL these families still "+
					"exported it: %v.\n\nThe reaper dropped their bookkeeping but not the "+
					"series, so a deleted pod's histograms, service-map edges and gauges "+
					"were exported for the life of the agent, and a saturation gauge kept "+
					"its alert active long after the pod was gone.", left)
			}
			sink.mu.Lock()
			seen := len(sink.seen)
			sink.mu.Unlock()
			if seen != 0 {
				t.Errorf("%d series still tracked after every one went idle", seen)
			}
		})
	}
}

func TestAReapedKernelSeriesIsRecreatedWhenTheWorkloadReturns(t *testing.T) {
	clock := time.Now()
	sink, reg := fullSurfaceSink(t, true, &clock)
	row := kernelRow(events.EventDNS, 0, kernelagg.BucketIndex(1_000_000), 1, 1_000_000, 0)

	sink.IngestKernel([]kernelagg.Row{row})
	clock = clock.Add(20 * time.Minute)
	sink.Reap(15 * time.Minute)
	sink.IngestKernel([]kernelagg.Row{row})

	metrics := gather(t, reg, "podtrace_workload_dns_latency_seconds")
	if len(metrics) != 1 {
		t.Fatalf("got %d DNS series after the workload came back, want 1", len(metrics))
	}
	if got := metrics[0].GetHistogram().GetSampleCount(); got != 1 {
		t.Errorf("sample count = %d, want 1: a returning workload must start from its new "+
			"traffic, not resume the distribution of the one that left", got)
	}
}

func TestDeletingAnUnknownKernelSeriesReportsNothing(t *testing.T) {
	clock := time.Now()
	sink, _ := fullSurfaceSink(t, true, &clock)
	if sink.kernelHist.delete("dns_latency_seconds", []string{"no", "such"}) {
		t.Error("deleting a series that was never observed reported success")
	}
	if sink.kernelHist.delete("not_a_family", nil) {
		t.Error("deleting from a family the kernel does not feed reported success")
	}
	if sink.deleteSeries(&seriesEntry{family: "not_a_family"}) {
		t.Error("an unknown family was reported deleted")
	}
}
