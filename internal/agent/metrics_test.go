package agent

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

// TestMetrics_RefreshEmitsDeltaOnly guards the invariant that
// CounterVecs are Add()'d by the per-tick delta, never Set() (which
// Prometheus forbids on counters). A bug here would either panic on a
// CounterVec.Set call or double-count events on every refresh.
func TestMetrics_RefreshEmitsDeltaOnly(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)
	router.Publish([]CRRule{
		mkRule("ns", "pt", []uint64{1, 2}, []events.EventType{events.EventDNS}, &recExp{name: "x"}),
	})

	// First refresh: counters report 0 (no events yet).
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 0 {
		t.Fatalf("initial counter should be 0, got %d", got)
	}

	// Bump events → refresh. Counter must increment by exactly the delta.
	router.Stats().incr(CRKey{"ns", "pt"}, 10)
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 10 {
		t.Fatalf("after incr(10): counter=%d want 10", got)
	}

	// Second refresh with no new events must NOT re-add the same 10.
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 10 {
		t.Fatalf("idle refresh double-counted: %d", got)
	}

	// Another bump.
	router.Stats().incr(CRKey{"ns", "pt"}, 5)
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 15 {
		t.Fatalf("cumulative: %d want 15", got)
	}
}

// TestMetrics_RemovedCRDropsLabels guards cardinality: once a CR is
// removed from the router's rule set, its label series should not
// linger in /metrics forever.
func TestMetrics_RemovedCRDropsLabels(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)
	router.Publish([]CRRule{
		mkRule("ns", "goes", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{name: "x"}),
	})
	router.Stats().incr(CRKey{"ns", "goes"}, 7)
	m.RefreshFromRouter(router)

	body := scrape(t, m)
	if !strings.Contains(body, `cr_name="goes"`) {
		t.Fatal("pre-removal: metric should have cr_name=goes")
	}

	// Remove the CR.
	router.Publish(nil)
	m.RefreshFromRouter(router)

	body = scrape(t, m)
	if strings.Contains(body, `active_cgroups{cr_namespace="ns",cr_name="goes"}`) {
		t.Error("post-removal: active_cgroups gauge still emits stale CR label")
	}
}

// TestMetrics_ActiveCRsTracksRouterSize asserts the global active_crs
// gauge matches len(rules) after each refresh.
func TestMetrics_ActiveCRsTracksRouterSize(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)

	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `active_crs`); got != 0 {
		t.Errorf("no CRs → active_crs=%d want 0", got)
	}

	router.Publish([]CRRule{
		mkRule("ns", "a", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{}),
		mkRule("ns", "b", []uint64{2}, []events.EventType{events.EventDNS}, &recExp{}),
	})
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `active_crs`); got != 2 {
		t.Errorf("active_crs=%d want 2", got)
	}
}

// TestMetrics_BackendDegraded_NoSeriesByDefault locks in the contract
// that keeps `max by(node)(podtrace_agent_backend_degraded) > 0` alerts
// quiet on healthy agents.
func TestMetrics_BackendDegraded_NoSeriesByDefault(t *testing.T) {
	m := NewMetrics()
	body := scrape(t, m)
	if strings.Contains(body, "podtrace_agent_backend_degraded") {
		t.Errorf("untouched backend_degraded GaugeVec must emit no output; got:\n%s", body)
	}
}

func TestMetrics_BackendDegraded_SetByReason(t *testing.T) {
	m := NewMetrics()
	m.BackendDegraded.WithLabelValues("permission_denied").Set(1)

	got := scrapeMetric(t, m, `backend_degraded{reason="permission_denied"}`)
	if got != 1 {
		t.Errorf("backend_degraded{reason=permission_denied} = %d, want 1", got)
	}
}

// TestMetrics_ProgramAttachFailures_ByProgramAndReason locks in the
// per-program counter contract: each (program, reason) tuple is a
// distinct series, increments are atomic, and the metric stays silent
// on healthy agents (no NaN/zero rows).
func TestMetrics_ProgramAttachFailures_ByProgramAndReason(t *testing.T) {
	m := NewMetrics()

	if scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_vfs_open",reason="permission_denied"}`) != 0 {
		t.Fatal("untouched program_attach_failures_total must emit no series")
	}

	m.RecordProgramAttachFailure("kprobe_vfs_open", "permission_denied")
	m.RecordProgramAttachFailure("kprobe_vfs_open", "permission_denied")
	m.RecordProgramAttachFailure("kprobe_do_futex", "kernel_too_old")

	if got := scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_vfs_open",reason="permission_denied"}`); got != 2 {
		t.Errorf("vfs_open permission_denied = %d, want 2", got)
	}
	if got := scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_do_futex",reason="kernel_too_old"}`); got != 1 {
		t.Errorf("do_futex kernel_too_old = %d, want 1", got)
	}
}

// TestMetrics_ProgramAttachFailures_EmptyReasonNormalized guards
// against a label cardinality regression: an empty reason from a
// poorly-classified error must collapse to "unknown" rather than
// emit a blank label that is hostile to Prometheus.
func TestMetrics_ProgramAttachFailures_EmptyReasonNormalized(t *testing.T) {
	m := NewMetrics()
	m.RecordProgramAttachFailure("kprobe_x", "")
	if got := scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_x",reason="unknown"}`); got != 1 {
		t.Errorf("empty reason should normalize to unknown; got %d", got)
	}
}

// TestMetrics_ProgramAttachFailures_NilReceiverSafe is the contract for
// the probe observer wiring: tracer construction must never panic when
// no metrics registry is set up (e.g. unit tests that build a tracer
// directly).
func TestMetrics_ProgramAttachFailures_NilReceiverSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil receiver panicked: %v", r)
		}
	}()
	var m *Metrics
	m.RecordProgramAttachFailure("kprobe_x", "permission_denied")
}

// TestMetrics_ExporterInit_EdgeTriggered pins the alert-friendly
// counter contract: one increment per ok→fail transition, repeat
// failures are silent until the CR returns to healthy.
func TestMetrics_ExporterInit_EdgeTriggered(t *testing.T) {
	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "broken"}
	bad := errors.New("unknown exporter type \"zipkin-direct\"")

	m.ObserveExporterInit(cr, bad)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 1 {
		t.Fatalf("first failure: counter = %d, want 1", got)
	}

	m.ObserveExporterInit(cr, bad)
	m.ObserveExporterInit(cr, bad)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 1 {
		t.Errorf("sustained failure inflated counter: %d, want 1", got)
	}

	m.ObserveExporterInit(cr, nil)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 1 {
		t.Errorf("recovery should not change the counter; got %d", got)
	}

	m.ObserveExporterInit(cr, bad)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 2 {
		t.Errorf("second edge: counter = %d, want 2", got)
	}
}

// TestMetrics_ExporterInit_ReasonClassification asserts that the
// reason label is sourced from ClassifyExporterError so dashboards
// keyed off the closed enum stay stable.
func TestMetrics_ExporterInit_ReasonClassification(t *testing.T) {
	m := NewMetrics()
	cases := []struct {
		cr     CRKey
		err    error
		reason string
	}{
		{CRKey{"ns", "a"}, errors.New("nil bundle payload"), "nil_payload"},
		{CRKey{"ns", "b"}, errors.New("missing endpoint for OTLP exporter"), "endpoint_missing"},
		{CRKey{"ns", "c"}, errors.New("tls handshake failed"), "tls_invalid"},
		{CRKey{"ns", "d"}, errors.New("missing api key"), "auth_missing"},
	}
	for _, tc := range cases {
		m.ObserveExporterInit(tc.cr, tc.err)
		sel := `exporter_init_failures_total{cr_namespace="` + tc.cr.Namespace + `",cr_name="` + tc.cr.Name + `",reason="` + tc.reason + `"}`
		if got := scrapeMetric(t, m, sel); got != 1 {
			t.Errorf("cr %s/%s expected reason=%q to register; got %d", tc.cr.Namespace, tc.cr.Name, tc.reason, got)
		}
	}
}

func TestMetrics_HandlerServesText(t *testing.T) {
	m := NewMetrics()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL) //nolint:noctx // test-only
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "podtrace_agent_active_crs") {
		t.Error("expected podtrace_agent_active_crs in /metrics output")
	}
}

// --- helpers ----------------------------------------------------------

// scrape hits the handler and returns the plaintext /metrics body.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// scrapeMetric parses a single metric out of the /metrics text and
// returns its int value. The selector is passed as "name" or
// "name{needle1,needle2}" where each needle is a label fragment
// (order-agnostic). Returns 0 when the line is not found.
func scrapeMetric(t *testing.T, m *Metrics, selector string) int {
	t.Helper()
	name, needles := parseSelector(selector)
	want := "podtrace_agent_" + name

	for _, line := range strings.Split(scrape(t, m), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !strings.HasPrefix(line, want) {
			continue
		}
		allNeedles := true
		for _, n := range needles {
			if !strings.Contains(line, n) {
				allNeedles = false
				break
			}
		}
		if !allNeedles {
			continue
		}
		idx := strings.LastIndex(line, " ")
		if idx < 0 {
			continue
		}
		var v int
		if _, err := sscan(line[idx+1:], &v); err == nil {
			return v
		}
	}
	return 0
}

// parseSelector splits "name{k1="v1",k2="v2"}" into ("name", [`k1="v1"`, `k2="v2"`]).
// Plain names without a label block return ("name", nil).
func parseSelector(sel string) (string, []string) {
	open := strings.IndexByte(sel, '{')
	if open < 0 {
		return sel, nil
	}
	name := sel[:open]
	inner := strings.TrimSuffix(sel[open+1:], "}")
	if inner == "" {
		return name, nil
	}
	return name, strings.Split(inner, ",")
}

// sscan is a tiny stand-in for fmt.Sscan to keep imports lean.
func sscan(s string, out *int) (int, error) {
	s = strings.TrimSpace(s)
	v := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, errParse
		}
		v = v*10 + int(c-'0')
	}
	if neg {
		v = -v
	}
	*out = v
	return 1, nil
}

var errParse = &parseErr{}

type parseErr struct{}

func (*parseErr) Error() string { return "parse error" }
