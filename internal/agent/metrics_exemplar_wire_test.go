package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/workloadmetrics"
)

const wireTraceID = "5b8aa5a2d2c872e8321cf37308d69df2"

func scrapeWith(t *testing.T, m *Metrics, accept string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d, body: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func tracedScrape(t *testing.T) *Metrics {
	t.Helper()

	m := NewMetrics()
	sink, err := workloadmetrics.New(m.Registerer(), workloadmetrics.Options{
		Lookup: func(cgroupID uint64) (events.K8sMetadata, bool) {
			return events.K8sMetadata{
				Namespace:     "shop",
				WorkloadName:  "checkout",
				WorkloadKind:  "Deployment",
				ContainerName: "app",
				PodName:       "checkout-0",
			}, true
		},
	})
	if err != nil {
		t.Fatalf("workloadmetrics.New: %v", err)
	}

	err = sink.Export(t.Context(), []*events.Event{{
		Type:      events.EventHTTPResp,
		CgroupID:  4242,
		LatencyNS: 7_000_000,
		Bytes:     256,
		Details:   "200",
		TraceID:   wireTraceID,
		SpanID:    "051581bf3cb55c13",
	}})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return m
}

func TestTheAgentScrapeCarriesExemplarsToAnOpenMetricsClient(t *testing.T) {
	body := scrapeWith(t, tracedScrape(t),
		"application/openmetrics-text; version=1.0.0; charset=utf-8")

	if !strings.Contains(body, wireTraceID) {
		t.Fatalf("the scrape carries no trace id at all.\n\nThis is the whole "+
			"metric-to-trace handoff: recording an exemplar the endpoint never "+
			"serves is worse than not recording one, because the gap is invisible.\n\n"+
			"l7 lines seen:\n%s", grepLines(body, "podtrace_workload_l7"))
	}

	var found bool
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "podtrace_workload_l7_request_duration_seconds_bucket") &&
			strings.Contains(line, "# {") && strings.Contains(line, wireTraceID) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no duration bucket carries an exemplar; the p99 spike is not "+
			"clickable into the trace behind it.\nbucket lines:\n%s",
			grepLines(body, "l7_request_duration_seconds_bucket"))
	}
}

func TestAPlainTextScrapeStillSucceedsWithoutExemplars(t *testing.T) {
	body := scrapeWith(t, tracedScrape(t), "text/plain;version=0.0.4")

	if !strings.Contains(body, "podtrace_workload_l7_requests_total") {
		t.Fatal("a plain-text scrape lost the metrics entirely")
	}
	if strings.Contains(body, "# {") {
		t.Error("exemplar syntax leaked into a plain-text scrape; a strict 0.0.4 " +
			"parser rejects the whole response over it")
	}
}

func TestADefaultScrapeIsNotBrokenByOpenMetricsBeingEnabled(t *testing.T) {
	body := scrapeWith(t, tracedScrape(t), "")

	if !strings.Contains(body, "podtrace_workload_l7_requests_total") {
		t.Fatal("a scrape with no Accept header lost the metrics")
	}
}

func grepLines(body, substr string) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return strings.Join(out, "\n")
}
