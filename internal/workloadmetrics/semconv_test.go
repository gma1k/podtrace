package workloadmetrics

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

func newSemconvSink(t *testing.T, limit int) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		SemanticConventions:  true,
		AttributeCardinality: limit,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func TestConventionNamesCarryNoPodtracePrefix(t *testing.T) {
	_, reg := newSemconvSink(t, 0)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	declared := map[string]bool{}
	for _, c := range newSemconvCollectors(true, 10).all() {
		ch := make(chan *prometheus.Desc, 8)
		go func(col prometheus.Collector) { col.Describe(ch); close(ch) }(c)
		for d := range ch {
			m := fqNameRe.FindStringSubmatch(d.String())
			if m != nil {
				declared[m[1]] = true
			}
		}
	}
	_ = families

	if len(declared) == 0 {
		t.Fatal("no convention families declared; this test would pass vacuously")
	}
	for name := range declared {
		if strings.HasPrefix(name, metricPrefix) {
			t.Errorf("%s carries the podtrace prefix. These names belong to the "+
				"OpenTelemetry convention: a stock dashboard queries "+
				"http_server_request_duration_seconds, so prefixing them makes the "+
				"whole surface unreachable to the dashboards it exists to serve", name)
		}
	}
	for _, want := range []string{semconvHTTPDuration, semconvRPCDuration, semconvDBDuration} {
		if !declared[want] {
			t.Errorf("convention family %q is not declared", want)
		}
	}
}

func TestConventionFamiliesAbsentUnlessRequested(t *testing.T) {
	reg := prometheus.NewRegistry()
	if _, err := New(reg, Options{}); err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := func() error {
		families, err := reg.Gather()
		if err != nil {
			return err
		}
		for _, f := range families {
			switch f.GetName() {
			case semconvHTTPDuration, semconvRPCDuration, semconvDBDuration:
				t.Errorf("%s exposed without SemanticConventions set; dual emission "+
					"doubles the L7 series and must be opt-in", f.GetName())
			}
		}
		return nil
	}(); err != nil {
		t.Fatalf("Gather: %v", err)
	}
}

func TestHTTPConventionCarriesMethodStatusAndProtocol(t *testing.T) {
	sink, reg := newSemconvSink(t, 0)

	if err := sink.Export(context.Background(), []*events.Event{{
		Type:       events.EventHTTPResp,
		LatencyNS:  5_000_000,
		Details:    "503",
		Error:      503,
		HTTPMethod: "POST",
		TCPState:   events.HTTPTransportH2TLS,
		K8s:        enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, semconvHTTPDuration)
	if len(series) != 1 {
		t.Fatalf("want 1 series, got %d", len(series))
	}
	got := labelsOf(series[0])

	for key, want := range map[string]string{
		"http_request_method":       "POST",
		"http_response_status_code": "503",
		"network_protocol_name":     "http/2",
		"service_name":              "checkout",
		"k8s_namespace_name":        "shop",
		"k8s_container_name":        "checkout",
	} {
		if got[key] != want {
			t.Errorf("label %q = %q, want %q", key, got[key], want)
		}
	}
}

func TestHTTPConventionEmitsRealCodeNotClass(t *testing.T) {
	for _, tc := range []struct{ details, want string }{
		{"200", "200"},
		{"404", "404"},
		{"301", "301"},
	} {
		t.Run(tc.details, func(t *testing.T) {
			sink, reg := newSemconvSink(t, 0)
			if err := sink.Export(context.Background(), []*events.Event{{
				Type: events.EventHTTPResp, LatencyNS: 1_000_000,
				Details: tc.details, HTTPMethod: "GET", K8s: enriched(),
			}}); err != nil {
				t.Fatalf("Export: %v", err)
			}

			series := gather(t, reg, semconvHTTPDuration)
			if len(series) != 1 {
				t.Fatalf("want 1 series, got %d", len(series))
			}
			if got := labelsOf(series[0])["http_response_status_code"]; got != tc.want {
				t.Errorf("status code = %q, want %q; the convention expects a code, and "+
					"a dashboard filtering status >= 500 cannot work on a class", got, tc.want)
			}
		})
	}
}

func TestUnknownMethodUsesTheConventionPlaceholder(t *testing.T) {
	sink, reg := newSemconvSink(t, 0)

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventHTTPResp, LatencyNS: 1_000_000,
		Details: "200", HTTPMethod: "", K8s: enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, semconvHTTPDuration)
	if len(series) != 1 {
		t.Fatalf("want 1 series, got %d", len(series))
	}
	if got := labelsOf(series[0])["http_request_method"]; got != "_OTHER" {
		t.Errorf("method = %q, want _OTHER; that is the convention's own placeholder "+
			"for a method outside the known set, and a blank label is not", got)
	}
}

func TestRPCAndDBConventionsMapTheirSystems(t *testing.T) {
	for _, tc := range []struct {
		typ    events.EventType
		family string
		labels map[string]string
	}{
		{events.EventGRPCMethod, semconvRPCDuration, map[string]string{"rpc_system": "grpc", "rpc_method": "/svc/Method"}},
		{events.EventRedisCmd, semconvDBDuration, map[string]string{"db_system_name": "redis", "db_operation_name": "GET"}},
		{events.EventMemcachedCmd, semconvDBDuration, map[string]string{"db_system_name": "memcached", "db_operation_name": "GET"}},
		{events.EventDBQuery, semconvDBDuration, map[string]string{"db_system_name": "other_sql", "db_operation_name": "GET"}},
	} {
		t.Run(fmt.Sprint(tc.typ), func(t *testing.T) {
			sink, reg := newSemconvSink(t, 0)
			if err := sink.Export(context.Background(), []*events.Event{{
				Type: tc.typ, LatencyNS: 2_000_000,
				Target: "/svc/Method", Details: "GET", K8s: enriched(),
			}}); err != nil {
				t.Fatalf("Export: %v", err)
			}

			series := gather(t, reg, tc.family)
			if len(series) != 1 {
				t.Fatalf("want 1 %s series, got %d", tc.family, len(series))
			}
			got := labelsOf(series[0])
			for k, want := range tc.labels {
				if got[k] != want {
					t.Errorf("label %q = %q, want %q", k, got[k], want)
				}
			}
		})
	}
}

func TestConventionsSkipProtocolsWithNoConvention(t *testing.T) {
	sink, reg := newSemconvSink(t, 0)

	for _, typ := range []events.EventType{events.EventKafkaProduce, events.EventFastCGIResp} {
		if err := sink.Export(context.Background(), []*events.Event{{
			Type: typ, LatencyNS: 1_000_000, K8s: enriched(),
		}}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}

	for _, family := range []string{semconvHTTPDuration, semconvRPCDuration, semconvDBDuration} {
		if got := len(gather(t, reg, family)); got != 0 {
			t.Errorf("%s got %d series from Kafka/FastCGI; neither has a server-duration "+
				"convention, so forcing them into one would misdescribe them", family, got)
		}
	}
	if got := len(gather(t, reg, "podtrace_workload_l7_requests_total")); got != 2 {
		t.Errorf("native l7 series = %d, want 2; protocols without a convention must "+
			"still appear on the native surface", got)
	}
}

func TestOpenAttributeValuesAreBounded(t *testing.T) {
	sink, reg := newSemconvSink(t, 3)

	var batch []*events.Event
	for i := 0; i < 20; i++ {
		batch = append(batch, &events.Event{
			Type:      events.EventGRPCMethod,
			LatencyNS: 1_000_000,
			Target:    fmt.Sprintf("/svc/Method%d", i),
			K8s:       enriched(),
		})
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, semconvRPCDuration)
	if len(series) > 4 {
		t.Errorf("got %d series from 20 distinct methods with a limit of 3; an "+
			"unbounded rpc_method lets one noisy client mint series without end",
			len(series))
	}

	var placeholder bool
	for _, m := range series {
		if labelsOf(m)["rpc_method"] == boundedValuesPlaceholder {
			placeholder = true
		}
	}
	if !placeholder {
		t.Error("the overflow tail was dropped rather than folded into the placeholder; " +
			"folding keeps the family's totals honest")
	}
}

func TestBoundedValuesBehaviour(t *testing.T) {
	b := newBoundedValues(2)

	if got := b.bound(""); got != "unknown" {
		t.Errorf("empty = %q, want unknown", got)
	}
	if got := b.bound("a"); got != "a" {
		t.Errorf("first = %q, want a", got)
	}
	if got := b.bound("b"); got != "b" {
		t.Errorf("second = %q, want b", got)
	}
	if got := b.bound("c"); got != boundedValuesPlaceholder {
		t.Errorf("third = %q, want %q", got, boundedValuesPlaceholder)
	}
	if got := b.bound("a"); got != "a" {
		t.Errorf("known value after saturation = %q, want a", got)
	}

	unbounded := newBoundedValues(-1)
	if got := unbounded.bound("anything"); got != "anything" {
		t.Errorf("disabled limit = %q, want passthrough", got)
	}
}

func TestUnattributedEventsProduceNoConventionSeries(t *testing.T) {
	sink, reg := newSemconvSink(t, 0)

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventHTTPResp, LatencyNS: 1_000_000, Details: "200", K8s: nil,
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := len(gather(t, reg, semconvHTTPDuration)); got != 0 {
		t.Errorf("got %d series without pod metadata; service_name would be empty, "+
			"which is worse than absent", got)
	}
}

func TestNetworkProtocolAndSystemFallbacks(t *testing.T) {
	if got := networkProtocolName(&events.Event{Type: events.EventExec}); got != "unknown" {
		t.Errorf("networkProtocolName fallback = %q, want unknown", got)
	}
	if got := rpcSystem(events.EventExec); got != "unknown" {
		t.Errorf("rpcSystem fallback = %q, want unknown", got)
	}
	if got := dbSystem(events.EventExec); got != "unknown" {
		t.Errorf("dbSystem fallback = %q, want unknown", got)
	}
	if got := statusCodeLabel(&events.Event{}); got != "0" {
		t.Errorf("statusCodeLabel with no status = %q, want 0", got)
	}
	if got := firstLine("GET\r\nHost: x"); got != "GET" {
		t.Errorf("firstLine = %q, want GET; a newline in a label value corrupts the "+
			"exposition format", got)
	}
	if got := semconvIdentity(events.K8sMetadata{Namespace: "n", WorkloadName: "w"}); got[2] != "unknown" {
		t.Errorf("missing container = %q, want unknown", got[2])
	}
}

func TestConventionRegistrationFailureIsReported(t *testing.T) {
	// Registering the whole sink twice collides on the native families
	// first, so it never reaches the convention path. Pre-registering a
	// collector that owns a convention name is what isolates it.
	reg := prometheus.NewRegistry()
	squatter := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: semconvHTTPDuration,
		Help: "collides with the convention family",
	})
	if err := reg.Register(squatter); err != nil {
		t.Fatalf("pre-register: %v", err)
	}

	_, err := New(reg, Options{SemanticConventions: true})
	if err == nil {
		t.Fatal("want an error when a convention name is already taken")
	}
	if !strings.Contains(err.Error(), "semantic-convention") {
		t.Errorf("error %q does not name which surface collided, so an operator "+
			"cannot tell the native families from the convention ones", err)
	}
}

func TestNetworkProtocolCoversEveryHTTPTransport(t *testing.T) {
	for _, tc := range []struct {
		transport uint32
		want      string
	}{
		{events.HTTPTransportPlaintext, "http/1.1"},
		{events.HTTPTransportTLS, "http/1.1"},
		{events.HTTPTransportH2C, "http/2"},
		{events.HTTPTransportH2TLS, "http/2"},
		{events.HTTPTransportH3, "http/3"},
	} {
		t.Run(fmt.Sprintf("transport_%d", tc.transport), func(t *testing.T) {
			got := networkProtocolName(&events.Event{
				Type: events.EventHTTPResp, TCPState: tc.transport,
			})
			if got != tc.want {
				t.Errorf("networkProtocolName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRecordSemconvIgnoresNonL7Events(t *testing.T) {
	sink, reg := newSemconvSink(t, 0)

	sink.recordSemconv(&events.Event{Type: events.EventDNS, K8s: enriched()}, 0.001)
	sink.recordSemconv(&events.Event{Type: events.EventTCPSend, K8s: enriched()}, 0.001)

	for _, family := range []string{semconvHTTPDuration, semconvRPCDuration, semconvDBDuration} {
		if got := len(gather(t, reg, family)); got != 0 {
			t.Errorf("%s got %d series from a non-L7 event", family, got)
		}
	}
}

func TestRecordSemconvIsInertWhenDisabled(t *testing.T) {
	sink, _ := newTestSink(t, 0)

	// Must not panic with a nil semconv collector set.
	sink.recordSemconv(&events.Event{
		Type: events.EventHTTPResp, Details: "200", K8s: enriched(),
	}, 0.005)
}

func TestRecordSemconvSkipsUnattributableEvents(t *testing.T) {
	// The early return when metadataFor fails: identity is mandatory on the
	// convention families, because service_name is what dashboards group by
	// and an empty one silently merges every workload into one row.
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{SemanticConventions: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sink.recordSemconv(&events.Event{
		Type: events.EventHTTPResp, Details: "200", CgroupID: 99, K8s: nil,
	}, 0.004)

	if got := len(gather(t, reg, semconvHTTPDuration)); got != 0 {
		t.Errorf("got %d series for an event with no resolvable identity", got)
	}
}

func TestHTTP2AndHTTP3RequestsCarryARealMethodLabel(t *testing.T) {
	for name, transport := range map[string]uint32{
		"h2c":   events.HTTPTransportH2C,
		"h2tls": events.HTTPTransportH2TLS,
		"h3":    events.HTTPTransportH3,
	} {
		t.Run(name, func(t *testing.T) {
			sink, reg := newSemconvSink(t, 0)

			if err := sink.Export(context.Background(), []*events.Event{{
				Type:       events.EventHTTPResp,
				LatencyNS:  3_000_000,
				Details:    "200",
				HTTPMethod: "POST",
				TCPState:   transport,
				K8s:        enriched(),
			}}); err != nil {
				t.Fatalf("Export: %v", err)
			}

			series := gather(t, reg, semconvHTTPDuration)
			if len(series) != 1 {
				t.Fatalf("want 1 series, got %d", len(series))
			}
			if got := labelsOf(series[0])["http_request_method"]; got != "POST" {
				t.Errorf("http_request_method = %q, want POST. The HPACK and QPACK decoders "+
					"recover :method, so %s traffic must not fall back to the _OTHER "+
					"placeholder the way it did before that was plumbed through", got, name)
			}
		})
	}
}

func TestAnEventWithNoRecoveredMethodStillUsesThePlaceholder(t *testing.T) {
	sink, reg := newSemconvSink(t, 0)

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventHTTPResp, LatencyNS: 1_000_000,
		Details: "200", HTTPMethod: "", TCPState: events.HTTPTransportH2C,
		K8s: enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, semconvHTTPDuration)
	if got := labelsOf(series[0])["http_request_method"]; got != "_OTHER" {
		t.Errorf("http_request_method = %q, want _OTHER; a late-joined stream whose :method was "+
			"indexed before capture attached genuinely has no method to report", got)
	}
}
