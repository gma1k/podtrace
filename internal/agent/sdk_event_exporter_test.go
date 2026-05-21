package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/exporter/bundle"
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
	body    []byte
}

func newCaptureServer() *captureServer {
	cs := &captureServer{}
	cs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cs.mu.Lock()
		defer cs.mu.Unlock()
		cs.hits++
		cs.lastReq = capturedReq{
			path:    r.URL.Path,
			method:  r.Method,
			headers: r.Header.Clone(),
			body:    body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	return cs
}

func (cs *captureServer) lastPath() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.lastReq.path
}

func (cs *captureServer) lastMethod() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.lastReq.method
}

func (cs *captureServer) lastBodyLen() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.lastReq.body)
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

// TestSDKEventExporter_GoldenOTLPWire is the golden-payload assertion for
// the agent's OTLP-only design.
func TestSDKEventExporter_GoldenOTLPWire(t *testing.T) {
	cases := []struct {
		name          string
		build         func(CRKey, *BundlePayload) (interface {
			Export(context.Context, []*events.Event) error
			Close(context.Context) error
			Name() string
		}, error)
		headerName  string
		credential  string
		extraAssert func(t *testing.T, cs *captureServer)
	}{
		{
			name: "otlp",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newOTLPEventExporter(k, b)
			},
		},
		{
			name: "jaeger",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newJaegerEventExporter(k, b)
			},
		},
		{
			name: "datadog",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newDataDogEventExporter(k, b)
			},
			headerName: "DD-API-KEY",
			credential: "dd-api-key-golden",
			extraAssert: func(t *testing.T, cs *captureServer) {
				if got := cs.lastHeader("Dd-Api-Key"); got != "dd-api-key-golden" {
					t.Errorf("DD-API-KEY = %q, want %q", got, "dd-api-key-golden")
				}
			},
		},
		{
			name: "splunk",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newSplunkEventExporter(k, b)
			},
			headerName: "X-SF-TOKEN",
			credential: "splunk-token-golden",
			extraAssert: func(t *testing.T, cs *captureServer) {
				if got := cs.lastHeader("X-Sf-Token"); got != "splunk-token-golden" {
					t.Errorf("X-SF-TOKEN = %q, want %q", got, "splunk-token-golden")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := newCaptureServer()
			defer cs.close()

			b := &BundlePayload{
				Type:       bundleType(tc.name),
				Endpoint:   cs.endpointHostPort(),
				Insecure:   true,
				HeaderName: tc.headerName,
				Credential: []byte(tc.credential),
			}
			exp, err := tc.build(CRKey{"ns", "cr"}, b)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			sendOneEventAndShutdown(t, exp)

			if cs.hitCount() == 0 {
				t.Fatal("captureServer received no request")
			}
			if got := cs.lastPath(); got != "/v1/traces" {
				t.Errorf("path = %q, want %q (proves OTLP/HTTP wire)", got, "/v1/traces")
			}
			if got := cs.lastMethod(); got != http.MethodPost {
				t.Errorf("method = %q, want POST", got)
			}
			if got := cs.lastHeader("Content-Type"); got != "application/x-protobuf" {
				t.Errorf("Content-Type = %q, want application/x-protobuf", got)
			}
			if cs.lastBodyLen() == 0 {
				t.Error("body is empty; expected serialized span data")
			}
			if tc.extraAssert != nil {
				tc.extraAssert(t, cs)
			}
		})
	}
}

// TestSDKEventExporter_LiteralHeadersPropagate confirms that
// bundle.Headers reach the receiver.
func TestSDKEventExporter_LiteralHeadersPropagate(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     bundle.TypeOTLP,
		Endpoint: cs.endpointHostPort(),
		Insecure: true,
		Headers: map[string]string{
			"X-Env":    "prod",
			"X-Tenant": "team-a",
		},
	}
	exp, err := newOTLPEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if got := cs.lastHeader("X-Env"); got != "prod" {
		t.Errorf("X-Env = %q, want prod", got)
	}
	if got := cs.lastHeader("X-Tenant"); got != "team-a" {
		t.Errorf("X-Tenant = %q, want team-a", got)
	}
}

func bundleType(name string) bundle.Type {
	switch name {
	case "otlp":
		return bundle.TypeOTLP
	case "jaeger":
		return bundle.TypeJaeger
	case "datadog":
		return bundle.TypeDataDog
	case "splunk":
		return bundle.TypeSplunk
	}
	return bundle.Type(name)
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