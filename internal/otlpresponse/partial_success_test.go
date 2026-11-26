package otlpresponse

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func exportAgainst(t *testing.T, status int, response *coltracepb.ExportTraceServiceResponse) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if response == nil {
			w.WriteHeader(status)
			return
		}
		body, _ := proto.Marshal(response)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	exp, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpointURL(srv.URL+"/v1/traces"),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	span := tracetest.SpanStub{
		Name: "op",
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{1},
			SpanID:  trace.SpanID{1},
		}),
	}.Snapshot()
	return exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{span})
}

func rejecting(spans int64) *coltracepb.ExportTraceServiceResponse {
	return &coltracepb.ExportTraceServiceResponse{
		PartialSuccess: &coltracepb.ExportTracePartialSuccess{RejectedSpans: spans, ErrorMessage: "invalid"},
	}
}

func TestRejectedSpansRecognisesTheExportersPartialSuccess(t *testing.T) {
	err := exportAgainst(t, http.StatusOK, rejecting(3))
	if err == nil {
		t.Fatal("the OTLP exporter no longer reports a partial success as an error; RejectedSpans has nothing to read")
	}
	n, ok := RejectedSpans(err)
	if !ok || n != 3 {
		t.Fatalf("RejectedSpans(%v) = %d, %v; want 3, true", err, n, ok)
	}
}

func TestRejectedSpansSumsJoinedPartialSuccesses(t *testing.T) {
	first := exportAgainst(t, http.StatusOK, rejecting(2))
	second := exportAgainst(t, http.StatusOK, rejecting(5))
	n, ok := RejectedSpans(errors.Join(first, fmt.Errorf("wrapped: %w", second)))
	if !ok || n != 7 {
		t.Fatalf("RejectedSpans = %d, %v; want 7, true", n, ok)
	}
}

func TestRejectedSpansRefusesAnythingElse(t *testing.T) {
	partial := exportAgainst(t, http.StatusOK, rejecting(1))
	failure := exportAgainst(t, http.StatusInternalServerError, nil)
	if failure == nil {
		t.Fatal("a 500 must fail the export")
	}
	cases := map[string]error{
		"nil":                 nil,
		"plain":               errors.New("boom"),
		"server error":        failure,
		"partial and failure": errors.Join(partial, failure),
		"empty join":          emptyJoin{},
		"look-alike":          PartialSuccess{RejectedItems: 4},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if n, ok := RejectedSpans(err); ok || n != 0 {
				t.Fatalf("RejectedSpans = %d, %v; want 0, false", n, ok)
			}
		})
	}
}

type emptyJoin struct{}

func (emptyJoin) Error() string   { return "empty" }
func (emptyJoin) Unwrap() []error { return nil }

type PartialSuccess struct{ RejectedItems int64 }

func (PartialSuccess) Error() string { return "look-alike" }

func TestPartialSuccessItemsHandlesPointersAndNegativeCounts(t *testing.T) {
	var nilPointer *PartialSuccess
	if _, ok := partialSuccessItems(nilPointer); ok {
		t.Fatal("a nil pointer is not a partial success")
	}
	if _, ok := partialSuccessItems(&PartialSuccess{RejectedItems: 1}); ok {
		t.Fatal("a type outside the OTLP exporters is not a partial success")
	}
	partial := exportAgainst(t, http.StatusOK, rejecting(-4))
	if n, ok := RejectedSpans(partial); !ok || n != 0 {
		t.Fatalf("RejectedSpans = %d, %v; want a negative count clamped to 0", n, ok)
	}
}

func TestRejectedItemsRefusesAnUnknownShape(t *testing.T) {
	cases := map[string]struct {
		value any
		want  int64
		ok    bool
	}{
		"int64":        {struct{ RejectedItems int64 }{7}, 7, true},
		"int":          {struct{ RejectedItems int }{3}, 3, true},
		"negative":     {struct{ RejectedItems int32 }{-1}, 0, true},
		"missing":      {struct{ Other int64 }{7}, 0, false},
		"not a number": {struct{ RejectedItems string }{"7"}, 0, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			n, ok := rejectedItems(reflect.ValueOf(tc.value))
			if n != tc.want || ok != tc.ok {
				t.Fatalf("rejectedItems = %d, %v; want %d, %v", n, ok, tc.want, tc.ok)
			}
		})
	}
}
