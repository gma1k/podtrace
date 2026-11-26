package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func smallTraces(n int) []encodedTrace {
	out := make([]encodedTrace, n)
	for i := range out {
		out[i] = encodedTrace{traceID: fmt.Sprintf("t%05d", i), elements: []encodedElement{element(80)}}
	}
	return out
}

func TestAnUnavailableCollectorAfterOneSuccessStopsTheExport(t *testing.T) {
	for _, code := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			traces := smallTraces(10_000)
			posts := 0
			var outcome exportOutcome
			sendTraceBatches(context.Background(), &outcome, traces, 1000, jsonArrayFrame, func(context.Context, []byte) error {
				posts++
				if posts == 1 {
					return nil
				}
				return statusError(code)
			})

			if posts != 2 {
				t.Fatalf("posts = %d, want 2: an unavailable collector must not be bisected", posts)
			}
			partial := asPartial(t, outcome.err())
			if partial.Retry(traces[0].traceID) {
				t.Fatal("the delivered first batch must not be retried")
			}
			for _, tr := range traces[12:] {
				if !partial.Retry(tr.traceID) {
					t.Fatalf("trace %s not retried", tr.traceID)
				}
			}
		})
	}
}

func TestACollectorRefusingEverythingAfterOneSuccessCostsABoundedNumberOfRequests(t *testing.T) {
	traces := smallTraces(10_000)
	posts := 0
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 1000, jsonArrayFrame, func(context.Context, []byte) error {
		posts++
		if posts == 1 {
			return nil
		}
		return statusError(http.StatusInternalServerError)
	})

	if posts > 32 {
		t.Fatalf("posts = %d for 10000 traces, want at most 32", posts)
	}
	partial := asPartial(t, outcome.err())
	delivered := 0
	for _, tr := range traces {
		if !partial.Retry(tr.traceID) {
			delivered++
		}
	}
	if delivered != 12 {
		t.Fatalf("%d traces settled, want only the 12 of the accepted first batch", delivered)
	}
}

func TestTheOnePerRequestFallbackKeepsDeliveringBetweenRefusedTraces(t *testing.T) {
	traces := smallTraces(600)
	for i := range traces {
		traces[i].elements = []encodedElement{{body: []byte(`"` + traces[i].traceID + strings.Repeat("e", 70) + `"`), spans: 1}}
	}
	refused := func(id string) bool { return id[len(id)-1]%2 == 0 }
	accepted := map[string]int{}
	posts := 0
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 1000, jsonArrayFrame, func(_ context.Context, body []byte) error {
		posts++
		var items []string
		if err := json.Unmarshal(body, &items); err != nil {
			t.Fatalf("body %q: %v", body, err)
		}
		for _, it := range items {
			if refused(it[:6]) {
				return statusError(http.StatusInternalServerError)
			}
		}
		for _, it := range items {
			accepted[it[:6]]++
		}
		return nil
	})

	if posts <= maxIsolationPosts {
		t.Fatalf("posts = %d, want the isolation budget exhausted so the fallback runs", posts)
	}
	partial := asPartial(t, outcome.err())
	for _, tr := range traces {
		switch {
		case refused(tr.traceID) && !partial.Retry(tr.traceID):
			t.Fatalf("refused trace %s not retried", tr.traceID)
		case !refused(tr.traceID) && accepted[tr.traceID] != 1:
			t.Fatalf("good trace %s accepted %d times, want 1", tr.traceID, accepted[tr.traceID])
		}
	}
}

func TestATooLargeBatchIsSplitAndATraceTooLargeAloneIsDropped(t *testing.T) {
	traces := []encodedTrace{
		{traceID: "a", elements: []encodedElement{element(40)}},
		{traceID: "b", elements: []encodedElement{element(40)}},
		{traceID: "huge", elements: []encodedElement{element(70)}},
		{traceID: "c", elements: []encodedElement{element(40)}},
	}
	var sizes []int
	var outcome exportOutcome
	sendTraceBatches(context.Background(), &outcome, traces, 200, jsonArrayFrame, func(_ context.Context, body []byte) error {
		sizes = append(sizes, len(body))
		if len(body) > 60 {
			return statusError(http.StatusRequestEntityTooLarge)
		}
		return nil
	})

	partial := asPartial(t, outcome.err())
	if len(partial.FailedTraces) != 0 {
		t.Fatalf("nothing may be retried: the small traces fit alone and the huge one never will; failed=%v", partial.FailedTraces)
	}
	if partial.SettledSpans["huge"] != 1 || partial.SettledSpans["a"] != 1 || partial.SettledSpans["c"] != 1 {
		t.Fatalf("settled = %v, want every trace settled", partial.SettledSpans)
	}
	if !strings.Contains(partial.Error(), "413") {
		t.Fatalf("error does not name the 413: %v", partial)
	}
}

func TestIsTooLargeAndIsSplittable(t *testing.T) {
	if !isTooLarge(statusError(http.StatusRequestEntityTooLarge)) || !isSplittable(statusError(http.StatusRequestEntityTooLarge)) {
		t.Fatal("413 must be split")
	}
	if isTooLarge(statusError(http.StatusBadRequest)) || isSplittable(statusError(http.StatusBadRequest)) {
		t.Fatal("400 must not be split")
	}
	if isSplittable(statusError(http.StatusServiceUnavailable)) {
		t.Fatal("503 must not be split")
	}
	if !isSplittable(statusError(http.StatusInternalServerError)) {
		t.Fatal("500 must be split")
	}
}

func TestStatusErrorDetailKeepsTheLibraryMessage(t *testing.T) {
	err := statusErrorDetail(http.StatusInternalServerError, fmt.Errorf("traces export: boom"))
	if err.Error() != "unexpected status code: 500: traces export: boom" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if !isServerError(err) {
		t.Fatal("a detailed 500 must still be a server error")
	}
	if !isPermanent(statusErrorDetail(http.StatusBadRequest, fmt.Errorf("bad"))) {
		t.Fatal("a detailed 400 must still be permanent")
	}
}

func TestExportOutcomeRejectIgnoresZeroAndKeepsTheLastReason(t *testing.T) {
	var outcome exportOutcome
	outcome.reject(0, fmt.Errorf("warning only"))
	if outcome.err() != nil {
		t.Fatalf("no rejected span must mean no error, got %v", outcome.err())
	}
	outcome.reject(2, fmt.Errorf("first"))
	outcome.reject(3, fmt.Errorf("second"))
	err := outcome.err()
	if RejectedSpans(err) != 5 || !strings.Contains(err.Error(), "second") {
		t.Fatalf("err = %v, want 5 rejected with the last reason", err)
	}
	if RejectedSpans(fmt.Errorf("unrelated")) != 0 || RejectedSpans(nil) != 0 {
		t.Fatal("an unrelated error carries no rejected spans")
	}
}

func TestAZipkinCollectorFailingAfterOneSuccessIsNotSentOneRequestPerTrace(t *testing.T) {
	var mu sync.Mutex
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		posts++
		n := posts
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	exp, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	traces := manyTraces(10_000)
	partial := asPartial(t, exp.ExportTraces(traces))

	mu.Lock()
	got := posts
	mu.Unlock()
	if got > maxIsolationPosts {
		t.Fatalf("collector received %d requests for 10000 traces, want at most %d", got, maxIsolationPosts)
	}
	retried := 0
	for _, tr := range traces {
		if partial.Retry(tr.TraceID) {
			retried++
		}
	}
	if retried == 0 || retried == len(traces) {
		t.Fatalf("retried %d of %d, want everything but the accepted first batch", retried, len(traces))
	}
}
