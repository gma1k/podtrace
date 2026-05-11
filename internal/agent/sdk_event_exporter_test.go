package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type captureServer struct {
	mu      sync.Mutex
	server  *httptest.Server
	hits    int
	lastReq capturedReq
}

type capturedReq struct {
	path    string
	method  string
	headers http.Header
}

func newCaptureServer() *captureServer {
	cs := &captureServer{}
	cs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		cs.hits++
		cs.lastReq = capturedReq{
			path:    r.URL.Path,
			method:  r.Method,
			headers: r.Header.Clone(),
		}
		w.WriteHeader(http.StatusOK)
	}))
	return cs
}

func (cs *captureServer) endpointHostPort() string {
	return strings.TrimPrefix(cs.server.URL, "http://")
}

func (cs *captureServer) hitCount() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.hits
}

func (cs *captureServer) lastHeader(name string) string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.lastReq.headers.Get(name)
}

func (cs *captureServer) close() {
	cs.server.Close()
}

func sendOneEventAndShutdown(t *testing.T, exp interface {
	Export(context.Context, []*events.Event) error
	Close(context.Context) error
}) {
	t.Helper()
	if err := exp.Export(context.Background(), []*events.Event{
		{Type: events.EventDNS, Timestamp: uint64(time.Now().UnixNano()), Target: "test.example"},
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exp.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSDKEventExporter_OTLPSendsToReceiver(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     "otlp",
		Endpoint: cs.endpointHostPort(),
		Insecure: true,
	}
	exp, err := newOTLPEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if cs.hitCount() == 0 {
		t.Fatal("captureServer received no OTLP request")
	}
}

func TestSDKEventExporter_JaegerSendsToReceiver(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     "jaeger",
		Endpoint: cs.endpointHostPort(),
		Insecure: true,
	}
	exp, err := newJaegerEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if cs.hitCount() == 0 {
		t.Fatal("captureServer received no request from Jaeger exporter")
	}
}

func TestSDKEventExporter_DataDogAppliesAPIKeyHeader(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:       "datadog",
		Endpoint:   cs.endpointHostPort(),
		Insecure:   true,
		HeaderName: "DD-API-KEY",
		Credential: []byte("sekret-api-key"),
	}
	exp, err := newDataDogEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if got := cs.lastHeader("Dd-Api-Key"); got != "sekret-api-key" {
		t.Errorf("DD-API-KEY header = %q, want %q", got, "sekret-api-key")
	}
}

func TestSDKEventExporter_SplunkAppliesTokenHeader(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:       "splunk",
		Endpoint:   cs.endpointHostPort(),
		Insecure:   true,
		HeaderName: "X-SF-TOKEN",
		Credential: []byte("hec-token"),
	}
	exp, err := newSplunkEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if got := cs.lastHeader("X-Sf-Token"); got != "hec-token" {
		t.Errorf("X-SF-TOKEN header = %q, want %q", got, "hec-token")
	}
}

func TestSDKEventExporter_NameIncludesBackend(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	cases := []struct {
		name    string
		build   func(CRKey, *BundlePayload) (interface{ Name() string }, error)
		wantSub string
	}{
		{
			"otlp",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newOTLPEventExporter(k, b)
				return e, err
			},
			"otlp",
		},
		{
			"jaeger",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newJaegerEventExporter(k, b)
				return e, err
			},
			"jaeger",
		},
		{
			"datadog",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newDataDogEventExporter(k, b)
				return e, err
			},
			"datadog",
		},
		{
			"splunk",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newSplunkEventExporter(k, b)
				return e, err
			},
			"splunk",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &BundlePayload{Type: "otlp", Endpoint: cs.endpointHostPort(), Insecure: true}
			exp, err := tc.build(CRKey{"ns", "cr"}, b)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if !strings.Contains(exp.Name(), tc.wantSub) {
				t.Errorf("Name() = %q; want substring %q", exp.Name(), tc.wantSub)
			}
		})
	}
}