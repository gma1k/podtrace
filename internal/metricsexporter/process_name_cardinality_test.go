package metricsexporter

import (
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/podtrace/podtrace/internal/events"
)

func TestProcessNameCardinalityBounded(t *testing.T) {
	const limit = 2
	const distinctNames = 8
	const prefix = "cardguard-proc-"

	saved := processCardinality
	processCardinality = newLabelCardinalityLimiter(limit)
	t.Cleanup(func() { processCardinality = saved })

	drive := func(e *events.Event) {
		ExportRTTMetricWithContext(e, "ns", "pod", "svc")
		ExportTCPMetricWithContext(e, "ns", "pod", "svc")
		ExportDNSMetricWithContext(e, "ns")
		ExportFileSystemMetricWithContext(e, "ns")
		ExportSchedSwitchMetricWithContext(e, "ns")
		ExportTLSMetricWithContext(e, "ns")
		ExportNetworkBandwidthMetricWithContext(e, "send", "ns", "pod", "svc")
		ExportFilesystemBandwidthMetricWithContext(e, "write", "ns")
	}

	switchTypes := []events.EventType{
		events.EventRedisCmd,
		events.EventMemcachedCmd,
		events.EventFastCGIResp,
		events.EventGRPCMethod,
		events.EventKafkaProduce,
		events.EventKafkaFetch,
	}

	for i := 0; i < distinctNames; i++ {
		name := prefix + strconv.Itoa(i)
		drive(&events.Event{
			Type:        events.EventDNS,
			ProcessName: name,
			LatencyNS:   1000,
			Bytes:       10,
		})
		for _, et := range switchTypes {
			HandleEventWithContext(&events.Event{
				Type:        et,
				ProcessName: name,
				Details:     "op",
				Target:      "tgt",
				LatencyNS:   1000,
				Bytes:       10,
			}, nil)
		}
	}

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	sawOther := false
	total := map[string]struct{}{}
	for _, mf := range mfs {
		perFamily := map[string]struct{}{}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() != "process_name" {
					continue
				}
				v := lp.GetValue()
				if v == "other" {
					sawOther = true
					continue
				}
				if strings.HasPrefix(v, prefix) {
					perFamily[v] = struct{}{}
					total[v] = struct{}{}
				}
			}
		}
		if len(perFamily) > limit {
			t.Errorf("family %q has %d distinct test process_name values (limit %d) — exporter is not bounding process_name",
				mf.GetName(), len(perFamily), limit)
		}
	}

	if len(total) > limit {
		t.Fatalf("across all families, %d distinct test process_name values admitted; limit is %d — process_name cardinality is unbounded", len(total), limit)
	}
	if len(total) == 0 {
		t.Fatal("no test process_name series produced — exporters did not run")
	}
	if !sawOther {
		t.Errorf("fed %d distinct names past a limit of %d but no \"other\" bucket appeared — overflow was not collapsed", distinctNames, limit)
	}
}
