package exporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

func manyTraces(n int) []*tracker.Trace {
	out := make([]*tracker.Trace, n)
	for i := range out {
		out[i] = traceWithIDs(fmt.Sprintf("%032x", i+1), fmt.Sprintf("%016x", i+1))
	}
	return out
}

type bodyRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (b *bodyRecorder) server(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		b.bodies = append(b.bodies, body)
		b.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (b *bodyRecorder) all() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.bodies...)
}

func TestZipkinSendsManyTracesInOneRequest(t *testing.T) {
	var rec bodyRecorder
	exp, err := NewZipkinExporter(rec.server(t, http.StatusAccepted).URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	if err := exp.ExportTraces(manyTraces(200)); err != nil {
		t.Fatal(err)
	}

	bodies := rec.all()
	if len(bodies) != 1 {
		t.Fatalf("200 traces took %d requests, want 1", len(bodies))
	}
	var spans []zipkinSpan
	if err := json.Unmarshal(bodies[0], &spans); err != nil {
		t.Fatalf("body is not a Zipkin v2 span array: %v", err)
	}
	if len(spans) != 200 {
		t.Fatalf("body carries %d spans, want 200", len(spans))
	}
}

func TestDataDogSendsManyTracesInOnePayload(t *testing.T) {
	var rec bodyRecorder
	exp, err := NewDataDogExporter(rec.server(t, http.StatusOK).URL, "", 1.0)
	if err != nil {
		t.Fatal(err)
	}

	if err := exp.ExportTraces(manyTraces(200)); err != nil {
		t.Fatal(err)
	}

	bodies := rec.all()
	if len(bodies) != 1 {
		t.Fatalf("200 traces took %d requests, want 1", len(bodies))
	}
	var payload [][]datadogSpan
	if err := json.Unmarshal(bodies[0], &payload); err != nil {
		t.Fatalf("body is not a v0.4 array of traces: %v", err)
	}
	if len(payload) != 200 {
		t.Fatalf("payload carries %d traces, want 200", len(payload))
	}
	for _, trace := range payload {
		if len(trace) != 1 {
			t.Fatalf("a trace was split inside the payload: %d spans", len(trace))
		}
	}
}

func TestACollectorFailingEveryRequestCostsAFewRequestsPerExport(t *testing.T) {
	var rec bodyRecorder
	exp, err := NewZipkinExporter(rec.server(t, http.StatusServiceUnavailable).URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.Repeat("x", 64*1024)
	traces := manyTraces(40)
	for _, tr := range traces {
		tr.Spans[0].Attributes = map[string]string{"blob": blob}
	}

	partial := asPartial(t, exp.ExportTraces(traces))

	if got := len(rec.all()); got > 8 {
		t.Fatalf("collector answering 503 to everything received %d requests for 40 traces, want at most 8 (one per trace before)", got)
	}
	for _, tr := range traces {
		if !partial.Retry(tr.TraceID) {
			t.Fatalf("trace %s was neither delivered nor scheduled for retry", tr.TraceID)
		}
	}
}

func TestAnUnreachableCollectorCostsOneRequestPerExport(t *testing.T) {
	traces := []encodedTrace{
		{traceID: "a", elements: []encodedElement{element(60)}},
		{traceID: "b", elements: []encodedElement{element(60)}},
		{traceID: "c", elements: []encodedElement{element(60)}},
	}
	for _, failure := range []error{errors.New("dial tcp: connection refused"), context.DeadlineExceeded, statusError(http.StatusTooManyRequests)} {
		posts := 0
		var outcome exportOutcome
		sendTraceBatches(context.Background(), &outcome, traces, 100, jsonArrayFrame, func(context.Context, []byte) error {
			posts++
			return failure
		})
		if posts != 1 {
			t.Errorf("%v: posted %d requests, want 1", failure, posts)
		}
		partial := asPartial(t, outcome.err())
		for _, id := range []string{"a", "b", "c"} {
			if !partial.Retry(id) {
				t.Errorf("%v: trace %s not scheduled for retry", failure, id)
			}
		}
	}
}

func TestExportStopsAtTheContextDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	exp, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = exp.ExportTracesContext(ctx, manyTraces(3))

	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("export took %s with a 100ms deadline", took)
	}
	if !asPartial(t, err).Retry(fmt.Sprintf("%032x", 1)) {
		t.Fatal("a trace cut off by the deadline must be retried")
	}
}

func element(size int) encodedElement {
	return encodedElement{body: []byte(strings.Repeat("e", size)), spans: 1}
}

func TestSendTraceBatchesSettlesThePrefixOfASplitTrace(t *testing.T) {
	traces := []encodedTrace{
		{traceID: "whole", elements: []encodedElement{element(40)}},
		{traceID: "split", elements: []encodedElement{element(40), element(40), element(40)}},
		{traceID: "later", elements: []encodedElement{element(40)}},
	}
	var posts int
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 100, jsonArrayFrame, func(context.Context, []byte) error {
		posts++
		if posts == 2 {
			return statusError(http.StatusServiceUnavailable)
		}
		return nil
	})

	if posts != 3 {
		t.Fatalf("posted %d batches, want 3: a refused trace must not stop the batches after it", posts)
	}
	partial := asPartial(t, outcome.err())
	if partial.Retry("whole") || partial.Retry("later") {
		t.Errorf("delivered traces must not be retried; failed=%v", partial.FailedTraces)
	}
	if !partial.Retry("split") {
		t.Error("the trace of the failed batch must be retried")
	}
	if got := partial.SettledPrefix("split"); got != 1 {
		t.Errorf("settled prefix of the split trace = %d, want the 1 span of the delivered batch", got)
	}
}

func TestSendTraceBatchesContinuesPastAPermanentRejection(t *testing.T) {
	traces := []encodedTrace{
		{traceID: "rejected", elements: []encodedElement{element(80)}},
		{traceID: "accepted", elements: []encodedElement{element(80)}},
	}
	var bodies []string
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 100, hecFrame, func(_ context.Context, body []byte) error {
		bodies = append(bodies, string(body))
		if len(bodies) == 1 {
			return statusError(http.StatusBadRequest)
		}
		return nil
	})

	if len(bodies) != 2 {
		t.Fatalf("posted %d batches, want both despite the rejection", len(bodies))
	}
	if !strings.HasSuffix(bodies[1], "\n") || strings.Contains(bodies[1], "\n\n") {
		t.Errorf("HEC body %q is not newline-terminated events", bodies[1])
	}
	err := outcome.err()
	partial := asPartial(t, err)
	if partial.Retry("rejected") || partial.Retry("accepted") {
		t.Errorf("no trace may be retried; failed=%v", partial.FailedTraces)
	}
	if !strings.Contains(err.Error(), "unexpected status code: 400") {
		t.Errorf("the rejection is not reported: %v", err)
	}
}

func TestSendTraceBatchesSendsAnOversizedElementAlone(t *testing.T) {
	traces := []encodedTrace{
		{traceID: "small", elements: []encodedElement{element(10)}},
		{traceID: "huge", elements: []encodedElement{element(500)}},
		{traceID: "tail", elements: []encodedElement{element(10)}},
	}
	var sizes []int
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 100, jsonArrayFrame, func(_ context.Context, body []byte) error {
		if !strings.HasPrefix(string(body), "[") || !strings.HasSuffix(string(body), "]") {
			t.Errorf("batch %q is not framed as an array", body)
		}
		sizes = append(sizes, len(body))
		return nil
	})

	if len(sizes) != 3 || sizes[1] != 502 {
		t.Fatalf("batch sizes = %v, want the oversized element in a batch of its own", sizes)
	}
	if err := outcome.err(); err != nil {
		t.Fatal(err)
	}
}

func TestSendTraceBatchesWithNothingToSendPostsNothing(t *testing.T) {
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, []encodedTrace{{traceID: "empty"}}, 100, jsonArrayFrame,
		func(context.Context, []byte) error {
			t.Fatal("posted an empty batch")
			return nil
		})
	if err := outcome.err(); err != nil {
		t.Fatal(err)
	}
}
