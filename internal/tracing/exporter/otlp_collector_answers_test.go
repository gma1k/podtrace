package exporter

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

type otlpAnswer struct {
	status   int
	response *coltracepb.ExportTraceServiceResponse
}

type otlpHTTPCollector struct {
	mu        sync.Mutex
	posts     int
	accepted  map[string]int
	bodySizes []int
	answer    func(traceIDs []string, size int) otlpAnswer
}

func startOTLPHTTPCollector(t *testing.T, answer func(traceIDs []string, size int) otlpAnswer) (*otlpHTTPCollector, string) {
	t.Helper()
	c := &otlpHTTPCollector{accepted: map[string]int{}, answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ids := requestTraceIDs(&req)
		a := c.answer(ids, len(body))
		c.mu.Lock()
		c.posts++
		c.bodySizes = append(c.bodySizes, len(body))
		if a.status == http.StatusOK {
			for _, id := range ids {
				c.accepted[id]++
			}
		}
		c.mu.Unlock()
		if a.response != nil {
			out, _ := proto.Marshal(a.response)
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.WriteHeader(a.status)
			_, _ = w.Write(out)
			return
		}
		w.WriteHeader(a.status)
	}))
	t.Cleanup(srv.Close)
	return c, srv.URL
}

func (c *otlpHTTPCollector) snapshot() (int, map[string]int, []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	accepted := make(map[string]int, len(c.accepted))
	for k, v := range c.accepted {
		accepted[k] = v
	}
	return c.posts, accepted, append([]int(nil), c.bodySizes...)
}

func requestTraceIDs(req *coltracepb.ExportTraceServiceRequest) []string {
	seen := map[string]bool{}
	var ids []string
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				id := hex.EncodeToString(sp.GetTraceId())
				if !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

func paddedTraces(n, attributeBytes int) []*tracker.Trace {
	out := make([]*tracker.Trace, n)
	pad := strings.Repeat("p", attributeBytes)
	for i := range out {
		traceID := fmt.Sprintf("%032x", i+1)
		out[i] = &tracker.Trace{
			TraceID: traceID,
			Spans: []*tracker.Span{{
				TraceID:    traceID,
				SpanID:     fmt.Sprintf("%016x", i+1),
				Operation:  "op",
				StartTime:  time.Now(),
				Duration:   time.Millisecond,
				Attributes: map[string]string{"pad": pad},
			}},
		}
	}
	return out
}

func newTestOTLPExporter(t *testing.T, endpoint string) *OTLPExporter {
	t.Helper()
	exp, err := NewOTLPExporter(endpoint, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	return exp
}

func partialSuccessResponse(rejected int64, message string) *coltracepb.ExportTraceServiceResponse {
	return &coltracepb.ExportTraceServiceResponse{
		PartialSuccess: &coltracepb.ExportTracePartialSuccess{RejectedSpans: rejected, ErrorMessage: message},
	}
}

func TestOTLPPartialSuccessIsADeliveryThatIsNotResent(t *testing.T) {
	collector, url := startOTLPHTTPCollector(t, func([]string, int) otlpAnswer {
		return otlpAnswer{status: http.StatusOK, response: partialSuccessResponse(1, "span name too long")}
	})
	exp := newTestOTLPExporter(t, url)

	err := exp.ExportTraces([]*tracker.Trace{
		traceWithIDs(goodTraceID, "1122334455667788"),
		traceWithIDs(badTraceID, "8877665544332211"),
	})

	var rejected *RejectedSpansError
	if !errors.As(err, &rejected) || rejected.Spans != 1 {
		t.Fatalf("err = %v, want a RejectedSpansError for 1 span", err)
	}
	if RejectedSpans(err) != 1 {
		t.Fatalf("RejectedSpans = %d, want 1", RejectedSpans(err))
	}
	if !strings.Contains(err.Error(), "span name too long") {
		t.Fatalf("the collector's message is lost: %v", err)
	}
	var partial *PartialExportError
	if errors.As(err, &partial) {
		t.Fatalf("a partial success must not ask for a retry: %v", partial.FailedTraces)
	}
	if posts, _, _ := collector.snapshot(); posts != 1 {
		t.Fatalf("posts = %d, want 1", posts)
	}
}

func TestOTLPPartialSuccessWithOnlyAWarningIsASuccess(t *testing.T) {
	_, url := startOTLPHTTPCollector(t, func([]string, int) otlpAnswer {
		return otlpAnswer{status: http.StatusOK, response: partialSuccessResponse(0, "deprecated attribute")}
	})
	exp := newTestOTLPExporter(t, url)

	if err := exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}); err != nil {
		t.Fatalf("a warning-only partial success must be a plain success, got %v", err)
	}
}

func TestOTLPRejectionsAlongsideAFailureAreCountedOnThePartialError(t *testing.T) {
	_, url := startOTLPHTTPCollector(t, func(ids []string, _ int) otlpAnswer {
		for _, id := range ids {
			if id == badTraceID {
				return otlpAnswer{status: http.StatusInternalServerError}
			}
		}
		return otlpAnswer{status: http.StatusOK, response: partialSuccessResponse(2, "too many attributes")}
	})
	exp := newTestOTLPExporter(t, url)

	err := exp.ExportTraces([]*tracker.Trace{
		traceWithIDs(goodTraceID, "1122334455667788"),
		traceWithIDs(badTraceID, "8877665544332211"),
	})

	partial := asPartial(t, err)
	if partial.Retry(goodTraceID) || !partial.Retry(badTraceID) {
		t.Fatalf("failed = %v, want only the refused trace retried", partial.FailedTraces)
	}
	if RejectedSpans(err) != 1 {
		t.Fatalf("RejectedSpans = %d, want 1 (clamped to the spans in the accepted request)", RejectedSpans(err))
	}
}

func TestOTLPSplitsABacklogIntoRequestsUnderTheBodyLimit(t *testing.T) {
	const bodyLimit = 1 << 20
	collector, url := startOTLPHTTPCollector(t, func(_ []string, size int) otlpAnswer {
		if size > bodyLimit {
			return otlpAnswer{status: http.StatusRequestEntityTooLarge}
		}
		return otlpAnswer{status: http.StatusOK}
	})
	exp := newTestOTLPExporter(t, url)
	traces := paddedTraces(3000, 1024)

	if err := exp.ExportTraces(traces); err != nil {
		t.Fatalf("export: %v", err)
	}

	posts, accepted, sizes := collector.snapshot()
	if posts < 2 {
		t.Fatalf("posts = %d, want the backlog split across requests", posts)
	}
	for _, size := range sizes {
		if size > bodyLimit {
			t.Fatalf("a request of %d bytes exceeds the 1 MiB ingress limit", size)
		}
	}
	for _, tr := range traces {
		if accepted[tr.TraceID] != 1 {
			t.Fatalf("trace %s accepted %d times, want 1", tr.TraceID, accepted[tr.TraceID])
		}
	}
}

func TestOTLPSplitsARequestTheCollectorFindsTooLarge(t *testing.T) {
	const bodyLimit = 20_000
	collector, url := startOTLPHTTPCollector(t, func(_ []string, size int) otlpAnswer {
		if size > bodyLimit {
			return otlpAnswer{status: http.StatusRequestEntityTooLarge}
		}
		return otlpAnswer{status: http.StatusOK}
	})
	exp := newTestOTLPExporter(t, url)
	traces := paddedTraces(200, 3000)

	if err := exp.ExportTraces(traces); err != nil {
		t.Fatalf("every trace fits on its own, so nothing may fail: %v", err)
	}
	_, accepted, _ := collector.snapshot()
	for _, tr := range traces {
		if accepted[tr.TraceID] != 1 {
			t.Fatalf("trace %s accepted %d times, want 1", tr.TraceID, accepted[tr.TraceID])
		}
	}
}

func TestOTLPDropsATraceTooLargeOnItsOwn(t *testing.T) {
	_, url := startOTLPHTTPCollector(t, func(_ []string, size int) otlpAnswer {
		if size > 10_000 {
			return otlpAnswer{status: http.StatusRequestEntityTooLarge}
		}
		return otlpAnswer{status: http.StatusOK}
	})
	exp := newTestOTLPExporter(t, url)
	traces := append(paddedTraces(3, 100), paddedTraces(4, 20_000)[3])

	err := exp.ExportTraces(traces)

	partial := asPartial(t, err)
	if len(partial.FailedTraces) != 0 {
		t.Fatalf("a trace too large on its own would be refused forever; failed=%v", partial.FailedTraces)
	}
	if !strings.Contains(err.Error(), "413") {
		t.Fatalf("error does not name the 413: %v", err)
	}
}

func TestOTLPDoesNotRetryARequestTheCollectorCannotParse(t *testing.T) {
	collector, url := startOTLPHTTPCollector(t, func([]string, int) otlpAnswer {
		return otlpAnswer{status: http.StatusBadRequest}
	})
	exp := newTestOTLPExporter(t, url)

	partial := asPartial(t, exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}))
	if partial.Retry(goodTraceID) {
		t.Fatal("a 400 is returned for the same payload forever; the trace must not be retried")
	}
	if posts, _, _ := collector.snapshot(); posts != 1 {
		t.Fatalf("posts = %d, want 1", posts)
	}
}

func TestOTLPIsolatesTheTraceACollectorRefusesWith500(t *testing.T) {
	_, url := startOTLPHTTPCollector(t, func(ids []string, _ int) otlpAnswer {
		for _, id := range ids {
			if id == badTraceID {
				return otlpAnswer{status: http.StatusInternalServerError}
			}
		}
		return otlpAnswer{status: http.StatusOK}
	})
	exp := newTestOTLPExporter(t, url)

	partial := asPartial(t, exp.ExportTraces([]*tracker.Trace{
		traceWithIDs(goodTraceID, "1122334455667788"),
		traceWithIDs(badTraceID, "8877665544332211"),
	}))
	if partial.Retry(goodTraceID) || !partial.Retry(badTraceID) {
		t.Fatalf("failed = %v, want only the refused trace retried", partial.FailedTraces)
	}
}

func TestOTLPRetriesEverythingWhenTheCollectorIsUnavailable(t *testing.T) {
	for _, code := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			collector, url := startOTLPHTTPCollector(t, func([]string, int) otlpAnswer {
				return otlpAnswer{status: code}
			})
			exp := newTestOTLPExporter(t, url)
			traces := paddedTraces(2000, 1024)

			partial := asPartial(t, exp.ExportTraces(traces))
			for _, tr := range traces {
				if !partial.Retry(tr.TraceID) {
					t.Fatalf("trace %s not retried", tr.TraceID)
				}
			}
			if posts, _, _ := collector.snapshot(); posts != 1 {
				t.Fatalf("posts = %d, want 1: an unavailable collector is not bisected", posts)
			}
		})
	}
}

type answeringGRPCCollector struct {
	coltracepb.UnimplementedTraceServiceServer
	answer func() (*coltracepb.ExportTraceServiceResponse, error)
}

func (c *answeringGRPCCollector) Export(context.Context, *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	return c.answer()
}

func startAnsweringGRPCCollector(t *testing.T, answer func() (*coltracepb.ExportTraceServiceResponse, error)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	coltracepb.RegisterTraceServiceServer(srv, &answeringGRPCCollector{answer: answer})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return "http://" + ln.Addr().String()
}

func TestOTLPGRPCPartialSuccessIsADelivery(t *testing.T) {
	useGRPCProtocol(t)
	endpoint := startAnsweringGRPCCollector(t, func() (*coltracepb.ExportTraceServiceResponse, error) {
		return partialSuccessResponse(1, "dropped"), nil
	})
	exp := newTestOTLPExporter(t, endpoint)

	err := exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")})
	var rejected *RejectedSpansError
	if !errors.As(err, &rejected) || rejected.Spans != 1 {
		t.Fatalf("err = %v, want a RejectedSpansError for 1 span", err)
	}
}

func TestOTLPGRPCStatusDecidesWhetherATraceIsRetried(t *testing.T) {
	useGRPCProtocol(t)
	cases := []struct {
		code  codes.Code
		retry bool
	}{
		{codes.InvalidArgument, false},
		{codes.Unauthenticated, false},
		{codes.Unavailable, true},
		{codes.ResourceExhausted, true},
		{codes.Internal, true},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			endpoint := startAnsweringGRPCCollector(t, func() (*coltracepb.ExportTraceServiceResponse, error) {
				return nil, status.Error(tc.code, "refused")
			})
			exp := newTestOTLPExporter(t, endpoint)

			partial := asPartial(t, exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}))
			if partial.Retry(goodTraceID) != tc.retry {
				t.Fatalf("retry = %v, want %v", partial.Retry(goodTraceID), tc.retry)
			}
		})
	}
}

func TestClassifyGRPCError(t *testing.T) {
	plain := errors.New("not a gRPC status")
	if got := classifyGRPCError(plain); got != plain || isPermanent(got) || isServerError(got) {
		t.Fatalf("a non-gRPC error must pass through unchanged, got %v", got)
	}
	if !isServerError(classifyGRPCError(status.Error(codes.Unknown, "x"))) {
		t.Fatal("Unknown must be isolated like an HTTP 500")
	}
	if !isPermanent(classifyGRPCError(status.Error(codes.PermissionDenied, "x"))) {
		t.Fatal("PermissionDenied must be permanent")
	}
	internal := classifyGRPCError(status.Error(codes.Internal, "boom"))
	if internal.Error() != status.Error(codes.Internal, "boom").Error() || errors.Unwrap(internal) == nil {
		t.Fatalf("the gRPC error text and chain must be kept, got %v", internal)
	}
	if got := classifyGRPCError(status.Error(codes.DeadlineExceeded, "x")); isPermanent(got) || isServerError(got) {
		t.Fatal("DeadlineExceeded must stop the export and be retried")
	}
}

func TestOTLPSpanBytesGrowsWithAttributesAndEvents(t *testing.T) {
	exp := &OTLPExporter{}
	small, err := exp.spanSnapshot(paddedTraces(1, 10)[0].Spans[0])
	if err != nil {
		t.Fatal(err)
	}
	large, err := exp.spanSnapshot(paddedTraces(1, 5000)[0].Spans[0])
	if err != nil {
		t.Fatal(err)
	}
	if otlpSpanBytes(large)-otlpSpanBytes(small) != 4990 {
		t.Fatalf("estimate does not follow the attribute size: small=%d large=%d", otlpSpanBytes(small), otlpSpanBytes(large))
	}
}

func TestResponseStatusIsRecordedOnlyForTheRequestsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: recordOTLPResponse(nil)}

	response := &otlpResponse{}
	req, _ := http.NewRequestWithContext(withOTLPResponse(context.Background(), response), http.MethodPost, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if response.statusCode() != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", response.statusCode())
	}

	unrelated, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, nil)
	resp, err = client.Do(unrelated)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var none *otlpResponse
	if none.statusCode() != 0 {
		t.Fatal("a nil recorder must report no status")
	}
}

type fixedStatusTransport struct {
	code int
}

func (f fixedStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.code, Body: http.NoBody, Request: req}, nil
}

func TestOTLPResponseRecordsOnlyValidHTTPStatusCodes(t *testing.T) {
	cases := []struct {
		code int
		want int
	}{
		{code: 99, want: 0},
		{code: 100, want: 100},
		{code: 503, want: 503},
		{code: 999, want: 999},
		{code: 1000, want: 0},
		{code: -1, want: 0},
		{code: 1 << 40, want: 0},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.code), func(t *testing.T) {
			r := &otlpResponse{}
			req := httptest.NewRequest(http.MethodPost, "http://collector/v1/traces", nil)
			req = req.WithContext(withOTLPResponse(req.Context(), r))
			resp, err := recordOTLPResponse(fixedStatusTransport{code: c.code}).RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			if resp.StatusCode != c.code {
				t.Fatalf("response status = %d, want %d passed through", resp.StatusCode, c.code)
			}
			if got := r.statusCode(); got != c.want {
				t.Fatalf("recorded status = %d, want %d", got, c.want)
			}
		})
	}
}
