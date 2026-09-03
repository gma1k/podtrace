package workloadmetrics

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/events"
)

var allEventTypes = map[events.EventType]string{
	events.EventDNS:            "EventDNS",
	events.EventConnect:        "EventConnect",
	events.EventTCPSend:        "EventTCPSend",
	events.EventTCPRecv:        "EventTCPRecv",
	events.EventWrite:          "EventWrite",
	events.EventRead:           "EventRead",
	events.EventFsync:          "EventFsync",
	events.EventSchedSwitch:    "EventSchedSwitch",
	events.EventTCPState:       "EventTCPState",
	events.EventPageFault:      "EventPageFault",
	events.EventOOMKill:        "EventOOMKill",
	events.EventUDPSend:        "EventUDPSend",
	events.EventUDPRecv:        "EventUDPRecv",
	events.EventHTTPReq:        "EventHTTPReq",
	events.EventHTTPResp:       "EventHTTPResp",
	events.EventLockContention: "EventLockContention",
	events.EventTCPRetrans:     "EventTCPRetrans",
	events.EventNetDevError:    "EventNetDevError",
	events.EventDBQuery:        "EventDBQuery",
	events.EventExec:           "EventExec",
	events.EventFork:           "EventFork",
	events.EventOpen:           "EventOpen",
	events.EventClose:          "EventClose",
	events.EventTLSHandshake:   "EventTLSHandshake",
	events.EventTLSError:       "EventTLSError",
	events.EventResourceLimit:  "EventResourceLimit",
	events.EventPoolAcquire:    "EventPoolAcquire",
	events.EventPoolRelease:    "EventPoolRelease",
	events.EventPoolExhausted:  "EventPoolExhausted",
	events.EventUnlink:         "EventUnlink",
	events.EventRename:         "EventRename",
	events.EventRedisCmd:       "EventRedisCmd",
	events.EventMemcachedCmd:   "EventMemcachedCmd",
	events.EventFastCGIReq:     "EventFastCGIReq",
	events.EventFastCGIResp:    "EventFastCGIResp",
	events.EventGRPCMethod:     "EventGRPCMethod",
	events.EventKafkaProduce:   "EventKafkaProduce",
	events.EventKafkaFetch:     "EventKafkaFetch",
	events.EventDNSQuery:       "EventDNSQuery",
	events.EventAFALG:          "EventAFALG",
	events.EventHTTP3:          "EventHTTP3",
	events.EventUSDT:           "EventUSDT",
}

var ignoredEventTypes = map[events.EventType]string{
	events.EventConnect:        "latency is covered by the network families",
	events.EventTCPState:       "state transitions are diagnostic detail, not a golden signal",
	events.EventPageFault:      "sampled in the kernel; a rate here would misrepresent it",
	events.EventOOMKill:        "a lifecycle event, better served by kube-state-metrics",
	events.EventLockContention: "no continuous consumer yet",
	events.EventTCPRetrans:     "no continuous consumer yet",
	events.EventNetDevError:    "no continuous consumer yet",
	events.EventExec:           "process lifecycle, not a workload signal",
	events.EventFork:           "process lifecycle, not a workload signal",
	events.EventTLSError:       "counted through errors_total when Error is set",
	events.EventResourceLimit:  "limits and usage belong to the resource families",
	events.EventPoolAcquire:    "pool metrics are diagnostic-surface only for now",
	events.EventPoolRelease:    "pool metrics are diagnostic-surface only for now",
	events.EventPoolExhausted:  "pool metrics are diagnostic-surface only for now",
	events.EventAFALG:          "crypto detection is a security signal, not a golden one",
	events.EventUSDT:           "user-defined probes have no fixed shape to aggregate",
}

func recordOne(t *testing.T, e *events.Event) (map[string][]*dto.Metric, bool) {
	t.Helper()

	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	base, ok := sink.baseLabelValues(e)
	if !ok {
		t.Fatalf("fixture is unattributed")
	}
	mapped := sink.record(e, base)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string][]*dto.Metric{}
	for _, f := range families {
		if strings.HasPrefix(f.GetName(), "podtrace_workload_metrics_") {
			continue
		}
		if len(f.GetMetric()) > 0 {
			out[f.GetName()] = f.GetMetric()
		}
	}
	return out, mapped
}

func TestEveryEventTypeIsAccountedFor(t *testing.T) {
	var unaccounted []string

	for typ, name := range allEventTypes {
		e := &events.Event{Type: typ, LatencyNS: 1_000_000, Bytes: 128, K8s: enriched()}
		families, mapped := recordOne(t, e)

		_, deliberatelyIgnored := ignoredEventTypes[typ]

		switch {
		case mapped && deliberatelyIgnored:
			t.Errorf("%s is listed as ignored but record() mapped it to %v", name, keysOf(families))
		case !mapped && !deliberatelyIgnored:
			unaccounted = append(unaccounted, name)
		case mapped && len(families) == 0 && typ != events.EventHTTPReq && typ != events.EventFastCGIReq:
			t.Errorf("%s was mapped but produced no series", name)
		}
	}

	sort.Strings(unaccounted)
	if len(unaccounted) > 0 {
		t.Errorf("these event types fall through record()'s default arm without being "+
			"listed in ignoredEventTypes: %v\n\nEvery type must be a deliberate choice. "+
			"Falling through means the plane silently ignores it, which is impossible to "+
			"notice from a dashboard.", unaccounted)
	}
}

func TestEventTypeMapsToExpectedFamilyAndLabels(t *testing.T) {
	for _, tc := range []struct {
		typ    events.EventType
		family string
		labels map[string]string
	}{
		{events.EventTCPSend, "podtrace_workload_network_latency_seconds", map[string]string{"direction": "egress", "transport": "tcp"}},
		{events.EventTCPRecv, "podtrace_workload_network_latency_seconds", map[string]string{"direction": "ingress", "transport": "tcp"}},
		{events.EventUDPSend, "podtrace_workload_network_latency_seconds", map[string]string{"direction": "egress", "transport": "udp"}},
		{events.EventUDPRecv, "podtrace_workload_network_latency_seconds", map[string]string{"direction": "ingress", "transport": "udp"}},

		{events.EventRead, "podtrace_workload_filesystem_latency_seconds", map[string]string{"operation": "read"}},
		{events.EventWrite, "podtrace_workload_filesystem_latency_seconds", map[string]string{"operation": "write"}},
		{events.EventFsync, "podtrace_workload_filesystem_latency_seconds", map[string]string{"operation": "fsync"}},
		{events.EventOpen, "podtrace_workload_filesystem_latency_seconds", map[string]string{"operation": "open"}},
		{events.EventClose, "podtrace_workload_filesystem_latency_seconds", map[string]string{"operation": "close"}},
		{events.EventUnlink, "podtrace_workload_filesystem_latency_seconds", map[string]string{"operation": "unlink"}},
		{events.EventRename, "podtrace_workload_filesystem_latency_seconds", map[string]string{"operation": "rename"}},

		{events.EventDNS, "podtrace_workload_dns_latency_seconds", nil},
		{events.EventDNSQuery, "podtrace_workload_dns_latency_seconds", nil},
		{events.EventSchedSwitch, "podtrace_workload_cpu_blocked_seconds", nil},
		{events.EventTLSHandshake, "podtrace_workload_tls_handshake_duration_seconds", nil},

		{events.EventGRPCMethod, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "grpc"}},
		{events.EventRedisCmd, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "redis"}},
		{events.EventMemcachedCmd, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "memcached"}},
		{events.EventFastCGIResp, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "fastcgi"}},
		{events.EventKafkaProduce, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "kafka"}},
		{events.EventKafkaFetch, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "kafka"}},
		{events.EventDBQuery, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "database"}},
		{events.EventHTTP3, "podtrace_workload_l7_requests_total", map[string]string{"protocol": "http3"}},
	} {
		t.Run(allEventTypes[tc.typ], func(t *testing.T) {
			families, _ := recordOne(t, &events.Event{
				Type: tc.typ, LatencyNS: 1_000_000, Bytes: 64, K8s: enriched(),
			})

			metrics, ok := families[tc.family]
			if !ok {
				t.Fatalf("no %s; got %v", tc.family, keysOf(families))
			}
			got := labelsOf(metrics[0])
			for key, want := range tc.labels {
				if got[key] != want {
					t.Errorf("label %q = %q, want %q", key, got[key], want)
				}
			}
			if got["namespace"] != "shop" || got["workload"] != "checkout" {
				t.Errorf("base labels missing: %v", got)
			}
		})
	}
}

func TestHTTPTransportSelectsTheProtocolLabel(t *testing.T) {
	for _, tc := range []struct {
		transport uint32
		want      string
	}{
		{events.HTTPTransportPlaintext, "http"},
		{events.HTTPTransportTLS, "http"},
		{events.HTTPTransportH2C, "http2"},
		{events.HTTPTransportH2TLS, "http2"},
		{events.HTTPTransportH3, "http3"},
	} {
		t.Run(fmt.Sprintf("transport_%d", tc.transport), func(t *testing.T) {
			got := protocolLabel(&events.Event{
				Type: events.EventHTTPResp, TCPState: tc.transport,
			})
			if got != tc.want {
				t.Errorf("protocol = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStatusClassBucketsEveryRange(t *testing.T) {
	for _, tc := range []struct {
		details string
		errCode int32
		want    string
	}{
		{"100", 0, "1xx"},
		{"200", 0, "2xx"},
		{"301", 0, "3xx"},
		{"404", 0, "4xx"},
		{"500", 0, "5xx"},
		{"599", 0, "5xx"},
		{"", 503, "5xx"},
		{"", 0, "unknown"},
		{"not-a-number", 0, "unknown"},
		{"99", 0, "unknown"},
		{"600", 0, "unknown"},
		{"200\nextra lines", 0, "2xx"},
	} {
		t.Run(fmt.Sprintf("%q_%d", tc.details, tc.errCode), func(t *testing.T) {
			got := statusClass(&events.Event{Details: tc.details, Error: tc.errCode})
			if got != tc.want {
				t.Errorf("statusClass = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestErrorKindGroupsEveryFailureFamily(t *testing.T) {
	for _, tc := range []struct {
		typ  events.EventType
		want string
	}{
		{events.EventHTTPResp, "l7"},
		{events.EventGRPCMethod, "l7"},
		{events.EventKafkaFetch, "l7"},
		{events.EventDNS, "dns"},
		{events.EventDNSQuery, "dns"},
		{events.EventTCPSend, "network"},
		{events.EventConnect, "network"},
		{events.EventTCPRetrans, "network"},
		{events.EventNetDevError, "network"},
		{events.EventRead, "filesystem"},
		{events.EventRename, "filesystem"},
		{events.EventTLSHandshake, "tls"},
		{events.EventTLSError, "tls"},
		{events.EventExec, "other"},
		{events.EventOOMKill, "other"},
	} {
		t.Run(allEventTypes[tc.typ], func(t *testing.T) {
			if got := errorKind(tc.typ); got != tc.want {
				t.Errorf("errorKind = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUnknownDimensionsFallBackWithoutPanicking(t *testing.T) {
	direction, transport := networkDimensions(events.EventExec)
	if direction != "unknown" || transport != "unknown" {
		t.Errorf("got (%q, %q), want unknown/unknown", direction, transport)
	}
	if got := filesystemOperation(events.EventExec); got != "unknown" {
		t.Errorf("filesystemOperation = %q, want unknown", got)
	}
	if got := protocolLabel(&events.Event{Type: events.EventExec}); got != "unknown" {
		t.Errorf("protocolLabel = %q, want unknown", got)
	}
}

func TestMissingMetadataFieldsBecomeUnknownNotEmpty(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{IncludePodLabel: true, IncludeProcessLabel: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventDNS,
		LatencyNS: 1_000_000,
		K8s: &events.K8sMetadata{
			Namespace:    "shop",
			WorkloadName: "checkout",
		},
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, "podtrace_workload_dns_latency_seconds")
	if len(series) != 1 {
		t.Fatalf("want 1 series, got %d", len(series))
	}
	got := labelsOf(series[0])
	for _, key := range []string{"workload_kind", "container", "pod", "process"} {
		if got[key] != "unknown" {
			t.Errorf("label %q = %q, want \"unknown\"; an empty label value is "+
				"indistinguishable from an absent series in PromQL", key, got[key])
		}
	}
}

func TestRegistrationFailureIsReported(t *testing.T) {
	reg := prometheus.NewRegistry()
	if _, err := New(reg, Options{}); err != nil {
		t.Fatalf("first New: %v", err)
	}
	_, err := New(reg, Options{})
	if err == nil {
		t.Fatal("want an error registering the same surface twice")
	}
	if !strings.Contains(err.Error(), "register workload metrics") {
		t.Errorf("error %q does not name what failed", err)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestEveryAdmittedFamilyIsEvictable(t *testing.T) {
	sink, _ := newTestSink(t, 0)

	seen := map[string]struct{}{}
	for typ := range allEventTypes {
		e := &events.Event{Type: typ, LatencyNS: 1_000_000, Bytes: 64, Error: 1, K8s: enriched()}
		base, ok := sink.baseLabelValues(e)
		if !ok {
			t.Fatal("fixture is unattributed")
		}
		sink.record(e, base)
	}

	sink.mu.Lock()
	for _, entry := range sink.seen {
		seen[entry.family] = struct{}{}
	}
	sink.mu.Unlock()

	if len(seen) == 0 {
		t.Fatal("no families were admitted; the walk is broken")
	}

	for family := range seen {
		_, isHistogram := sink.c.histogramFor(family)
		_, isCounter := sink.c.counterFor(family)
		if !isHistogram && !isCounter {
			t.Errorf("family %q is admitted but resolves to no collector, so Reap "+
				"cannot delete it: it will hold budget forever", family)
		}
	}
}

func TestFamilyLookupsDoNotClaimUnknownNames(t *testing.T) {
	sink, _ := newTestSink(t, 0)
	for _, bogus := range []string{"", "nope", "l7_requests", "dns_latency"} {
		if _, ok := sink.c.histogramFor(bogus); ok {
			t.Errorf("histogramFor(%q) claimed a collector", bogus)
		}
		if _, ok := sink.c.counterFor(bogus); ok {
			t.Errorf("counterFor(%q) claimed a collector", bogus)
		}
	}
}
