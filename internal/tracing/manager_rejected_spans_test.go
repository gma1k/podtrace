package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/gma1k/podtrace/internal/config"
)

func TestRejectedSpansAreDeliveredOnceAndCounted(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		body, _ := proto.Marshal(&coltracepb.ExportTraceServiceResponse{
			PartialSuccess: &coltracepb.ExportTracePartialSuccess{RejectedSpans: 1, ErrorMessage: "attribute too long"},
		})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	m := managerWithOnly(t, func() { config.OTLPEndpoint = srv.URL })
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	trackSpan(m, "aabbccddeeff00112233445566778899", "1122334455667788")
	trackSpan(m, "99887766554433221100ffeeddccbbaa", "8877665544332211")

	m.exportTraces(context.Background(), true)
	m.exportTraces(context.Background(), true)

	if got := posts.Load(); got != 1 {
		t.Fatalf("collector received %d posts, want 1: accepted spans must not be re-sent", got)
	}
	status := m.ExportStatus()
	if len(status) != 1 {
		t.Fatalf("status = %+v", status)
	}
	st := status[0]
	if st.SucceededBatches != 1 || st.FailedBatches != 0 || st.RejectedSpans != 1 || st.LastError != "" {
		t.Fatalf("status = %+v, want one delivered batch with one rejected span", st)
	}
}
