package exporter

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/safeconv"
)

type poisonCollector struct {
	mu       sync.Mutex
	poison   map[string]bool
	posts    int
	accepted map[string]int
}

func (c *poisonCollector) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var spans []zipkinSpan
		if err := json.Unmarshal(body, &spans); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.posts++
		for _, s := range spans {
			if c.poison[s.TraceID] {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		for _, s := range spans {
			c.accepted[s.TraceID]++
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIsolationDeliversEveryTraceButTheOneTheCollectorRefuses(t *testing.T) {
	traces := manyTraces(200)
	poisoned := traces[137].TraceID
	collector := &poisonCollector{poison: map[string]bool{poisoned: true}, accepted: map[string]int{}}
	exp, err := NewZipkinExporter(collector.server(t).URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces(traces))

	for _, tr := range traces {
		got := collector.accepted[tr.TraceID]
		switch {
		case tr.TraceID == poisoned && (got != 0 || !partial.Retry(tr.TraceID)):
			t.Errorf("refused trace: accepted %d times, retried=%v; want 0 and retried", got, partial.Retry(tr.TraceID))
		case tr.TraceID != poisoned && (got != 1 || partial.Retry(tr.TraceID)):
			t.Errorf("trace %s: accepted %d times, retried=%v; want delivered exactly once", tr.TraceID, got, partial.Retry(tr.TraceID))
		}
	}
	const oneRequestPerTrace = 200
	if collector.posts > 17 {
		t.Errorf("isolating 1 refused trace among 200 took %d requests, want at most 17 (one request per trace took %d)", collector.posts, oneRequestPerTrace)
	}
}

func TestIsolationFindsSeveralRefusedTraces(t *testing.T) {
	traces := manyTraces(64)
	poison := map[string]bool{traces[3].TraceID: true, traces[40].TraceID: true, traces[41].TraceID: true}
	collector := &poisonCollector{poison: poison, accepted: map[string]int{}}
	exp, err := NewZipkinExporter(collector.server(t).URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces(traces))

	for _, tr := range traces {
		if poison[tr.TraceID] {
			if !partial.Retry(tr.TraceID) {
				t.Errorf("refused trace %s not retried", tr.TraceID)
			}
			continue
		}
		if collector.accepted[tr.TraceID] != 1 || partial.Retry(tr.TraceID) {
			t.Errorf("trace %s: accepted %d times, retried=%v; want delivered exactly once",
				tr.TraceID, collector.accepted[tr.TraceID], partial.Retry(tr.TraceID))
		}
	}
}

func TestARefusedTraceAloneInItsBatchDoesNotStopTheBatchesAfterIt(t *testing.T) {
	traces := []encodedTrace{
		{traceID: "refused", elements: []encodedElement{element(80)}},
		{traceID: "next", elements: []encodedElement{element(80)}},
		{traceID: "last", elements: []encodedElement{element(80)}},
	}
	var delivered []string
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 100, jsonArrayFrame, func(_ context.Context, body []byte) error {
		if len(delivered) == 0 && !strings.Contains(string(body), "accepted-marker") {
			delivered = append(delivered, "accepted-marker")
			return statusError(http.StatusInternalServerError)
		}
		delivered = append(delivered, string(body))
		return nil
	})

	partial := asPartial(t, outcome.err())
	if !partial.Retry("refused") || partial.Retry("next") || partial.Retry("last") {
		t.Fatalf("want only the refused trace retried; failed=%v", partial.FailedTraces)
	}
	if len(delivered) != 3 {
		t.Fatalf("posted %d requests, want 3", len(delivered))
	}
}

func TestManyRefusedTracesFallBackToOneRequestPerTrace(t *testing.T) {
	traces := manyTraces(400)
	poison := map[string]bool{}
	for i, tr := range traces {
		if i%3 == 2 {
			poison[tr.TraceID] = true
		}
	}
	collector := &poisonCollector{poison: poison, accepted: map[string]int{}}
	exp, err := NewZipkinExporter(collector.server(t).URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces(traces))

	for _, tr := range traces {
		if poison[tr.TraceID] {
			if !partial.Retry(tr.TraceID) {
				t.Fatalf("refused trace %s not retried", tr.TraceID)
			}
			continue
		}
		if collector.accepted[tr.TraceID] != 1 || partial.Retry(tr.TraceID) {
			t.Fatalf("trace %s: accepted %d times, retried=%v; with a third of the traces refused every good one must still be delivered once",
				tr.TraceID, collector.accepted[tr.TraceID], partial.Retry(tr.TraceID))
		}
	}
	if limit := 1 + maxIsolationPosts + len(traces); collector.posts > limit {
		t.Fatalf("posted %d requests, want at most %d (one per trace plus the isolation budget)", collector.posts, limit)
	}
}

func TestACollectorFailingEverythingIsJudgedDownAfterFewRequests(t *testing.T) {
	collector := &poisonCollector{poison: map[string]bool{}, accepted: map[string]int{}}
	traces := manyTraces(500)
	for _, tr := range traces {
		collector.poison[tr.TraceID] = true
	}
	exp, err := NewZipkinExporter(collector.server(t).URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces(traces))

	if collector.posts > 3+2*bits.Len(uint(len(traces))) {
		t.Fatalf("a collector refusing everything received %d requests for %d traces", collector.posts, len(traces))
	}
	for _, tr := range traces {
		if !partial.Retry(tr.TraceID) {
			t.Fatalf("trace %s neither delivered nor retried", tr.TraceID)
		}
	}
}

func TestAfterAnySuccessA5xxNeverStopsTheExport(t *testing.T) {
	traces := []encodedTrace{
		{traceID: "ok", elements: []encodedElement{element(80)}},
		{traceID: "bad1", elements: []encodedElement{element(80)}},
		{traceID: "bad2", elements: []encodedElement{element(80)}},
		{traceID: "bad3", elements: []encodedElement{element(80)}},
		{traceID: "bad4", elements: []encodedElement{element(80)}},
		{traceID: "last", elements: []encodedElement{element(80)}},
	}
	posts := 0
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 100, jsonArrayFrame, func(context.Context, []byte) error {
		posts++
		if posts >= 2 && posts <= 5 {
			return statusError(http.StatusInternalServerError)
		}
		return nil
	})

	partial := asPartial(t, outcome.err())
	if posts != 6 || partial.Retry("last") || partial.Retry("ok") {
		t.Fatalf("posts=%d failed=%v; want the batch after four refused ones delivered", posts, partial.FailedTraces)
	}
}

func TestThreeRefusedSingleTracesBeforeAnySuccessStopTheExport(t *testing.T) {
	var traces []encodedTrace
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		traces = append(traces, encodedTrace{traceID: id, elements: []encodedElement{element(80)}})
	}
	posts := 0
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 100, jsonArrayFrame, func(context.Context, []byte) error {
		posts++
		return statusError(http.StatusBadGateway)
	})

	if posts != collectorDownAfter {
		t.Fatalf("posted %d single-trace batches to a failing collector, want %d", posts, collectorDownAfter)
	}
	partial := asPartial(t, outcome.err())
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if !partial.Retry(id) {
			t.Errorf("trace %s not retried", id)
		}
	}
}

func TestOnePerRequestFallbackStopsWhenTheCollectorStopsAnswering(t *testing.T) {
	shares := []batchShare{
		{traceID: "a", elements: []encodedElement{element(5)}, spans: 1},
		{traceID: "b", elements: []encodedElement{element(5)}, spans: 1},
		{traceID: "c", elements: []encodedElement{element(5)}, spans: 1},
	}
	var outcome exportOutcome
	posts := 0
	s := &batchSender{ctx: context.Background(), outcome: &outcome, frame: jsonArrayFrame, answered: true,
		isolationPosts: maxIsolationPosts, post: func(context.Context, []byte) error {
			posts++
			if posts == 1 {
				return nil
			}
			return context.DeadlineExceeded
		}}

	s.resolve(shares, statusError(http.StatusInternalServerError))

	partial := asPartial(t, outcome.err())
	if posts != 2 || partial.Retry("a") || !partial.Retry("b") || !partial.Retry("c") {
		t.Fatalf("posts=%d failed=%v; want a delivered, b timed out, c not sent", posts, partial.FailedTraces)
	}
}

func TestIsolationInvariantsOverRandomLayouts(t *testing.T) {
	for seed := range uint64(500) {
		checkIsolationInvariants(t, seed)
	}
}

type seededLayout struct {
	seed, draws uint64
}

func (l *seededLayout) IntN(n int) int {
	var in [16]byte
	binary.LittleEndian.PutUint64(in[:8], l.seed)
	binary.LittleEndian.PutUint64(in[8:], l.draws)
	l.draws++
	sum := sha256.Sum256(in[:])
	return safeconv.Uint64ToInt(binary.LittleEndian.Uint64(sum[:8]) % safeconv.IntToUint64(n))
}

func checkIsolationInvariants(t *testing.T, seed uint64) {
	t.Helper()
	rng := &seededLayout{seed: seed}
	collectorDown := rng.IntN(10) == 0
	poisonEvery := 0
	if rng.IntN(2) == 0 {
		poisonEvery = 2 + rng.IntN(40)
	}

	var traces []encodedTrace
	poison := map[string]bool{}
	element := 0
	for i := range 1 + rng.IntN(60) {
		tr := encodedTrace{traceID: fmt.Sprintf("t%02d", i)}
		for j := range 1 + rng.IntN(6) {
			id := fmt.Sprintf("%s#%d", tr.traceID, j)
			pad := strings.Repeat("x", rng.IntN(40))
			tr.elements = append(tr.elements, encodedElement{body: []byte(`"` + id + "|" + pad + `"`), spans: 1})
			element++
			if poisonEvery > 0 && element%poisonEvery == 0 {
				poison[id] = true
			}
		}
		traces = append(traces, tr)
	}

	accepted := map[string]int{}
	posts := 0
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 40+rng.IntN(300), jsonArrayFrame, func(_ context.Context, body []byte) error {
		posts++
		var items []string
		if err := json.Unmarshal(body, &items); err != nil {
			t.Fatalf("seed %d: body %q is not a JSON array: %v", seed, body, err)
		}
		if collectorDown {
			return statusError(http.StatusServiceUnavailable)
		}
		for _, it := range items {
			if poison[strings.SplitN(it, "|", 2)[0]] {
				return statusError(http.StatusInternalServerError)
			}
		}
		for _, it := range items {
			accepted[strings.SplitN(it, "|", 2)[0]]++
		}
		return nil
	})

	var partial *PartialExportError
	if err := outcome.err(); err != nil {
		partial = asPartial(t, err)
	}
	retried := func(id string) bool { return partial != nil && partial.Retry(id) }
	prefix := func(id string) int {
		if partial == nil {
			return 0
		}
		return partial.SettledPrefix(id)
	}

	for _, tr := range traces {
		delivered := 0
		for j := range tr.elements {
			n := accepted[fmt.Sprintf("%s#%d", tr.traceID, j)]
			if n > 1 {
				t.Fatalf("seed %d: element %s#%d accepted %d times", seed, tr.traceID, j, n)
			}
			if n == 1 {
				if delivered != j {
					t.Fatalf("seed %d: %s#%d accepted after an earlier span of its trace was not", seed, tr.traceID, j)
				}
				delivered++
			}
		}
		switch {
		case retried(tr.traceID):
			if prefix(tr.traceID) != delivered {
				t.Fatalf("seed %d: trace %s settled prefix %d, but %d leading spans were accepted",
					seed, tr.traceID, prefix(tr.traceID), delivered)
			}
		case delivered != len(tr.elements):
			t.Fatalf("seed %d: trace %s lost: %d of %d spans accepted and not retried",
				seed, tr.traceID, delivered, len(tr.elements))
		}
	}

	if limit := 3 + 2*bits.Len(uint(element)); collectorDown && posts > limit {
		t.Fatalf("seed %d: a collector failing everything received %d requests for %d spans, want at most %d", seed, posts, element, limit)
	}
	if !collectorDown && len(poison) <= 2 {
		for _, tr := range traces {
			bad := false
			for j := range tr.elements {
				bad = bad || poison[fmt.Sprintf("%s#%d", tr.traceID, j)]
			}
			if !bad && retried(tr.traceID) {
				t.Fatalf("seed %d: healthy trace %s was not delivered with only %d refused spans", seed, tr.traceID, len(poison))
			}
		}
	}
}

func TestExportersReportTheStatusCodeOfTheIsolatedFailure(t *testing.T) {
	srv, _ := failingFor(badTraceID, http.StatusInternalServerError)
	t.Cleanup(srv.Close)
	exp, err := NewSplunkExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatal(err)
	}

	err = exp.ExportTraces([]*tracker.Trace{
		traceWithIDs(goodTraceID, "1122334455667788"),
		traceWithIDs(badTraceID, "8877665544332211"),
	})

	if !strings.Contains(err.Error(), "batch of 1 traces: unexpected status code: 500") {
		t.Fatalf("error does not name the isolated failure: %v", err)
	}
	partial := asPartial(t, err)
	if partial.Retry(goodTraceID) || !partial.Retry(badTraceID) {
		t.Fatalf("want only the refused trace retried; failed=%v", partial.FailedTraces)
	}
}

func TestIsServerError(t *testing.T) {
	cases := map[error]bool{
		statusError(http.StatusInternalServerError): true,
		statusError(http.StatusServiceUnavailable):  true,
		statusError(http.StatusTooManyRequests):     false,
		statusError(http.StatusBadRequest):          false,
		context.DeadlineExceeded:                    false,
		fmt.Errorf("wrapped: %w", statusError(502)): true,
	}
	for err, want := range cases {
		if got := isServerError(err); got != want {
			t.Errorf("isServerError(%v) = %v, want %v", err, got, want)
		}
	}
}
