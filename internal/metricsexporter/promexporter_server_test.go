package metricsexporter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/podtrace/podtrace/internal/config"
)

// TestRateLimitMiddleware_Throttled drives enough requests through the shared
// limiter to exhaust its burst, exercising the 429 branch of rateLimitMiddleware
// that the allowed-only tests do not reach.
func TestRateLimitMiddleware_Throttled(t *testing.T) {
	original := limiter
	limiter = rate.NewLimiter(rate.Every(time.Second/time.Duration(config.RateLimitPerSec)), config.RateLimitBurst)
	t.Cleanup(func() { limiter = original })

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rateLimitMiddleware(next)

	var sawOK, sawThrottled bool
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		switch rr.Code {
		case http.StatusOK:
			sawOK = true
		case http.StatusTooManyRequests:
			sawThrottled = true
		default:
			t.Fatalf("unexpected status code %d", rr.Code)
		}
		if sawOK && sawThrottled {
			break
		}
	}

	if !sawOK {
		t.Errorf("expected at least one allowed (200) response")
	}
	if !sawThrottled {
		t.Errorf("expected at least one throttled (429) response after exhausting burst")
	}
}

// TestStartServer_RejectNonLoopback exercises the StartServer branch that
// rejects a non-loopback metrics address when the insecure-allow flag is unset
// and falls back to the default loopback address.
func TestStartServer_RejectNonLoopback(t *testing.T) {
	t.Setenv("PODTRACE_METRICS_ADDR", "8.8.8.8:0")

	srv := StartServer()
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}
	defer srv.Shutdown()

	if srv.server.Addr == "8.8.8.8:0" {
		t.Errorf("expected non-loopback address to be rejected and replaced with default, got %q", srv.server.Addr)
	}
}

// TestStartServer_WithPprof exercises the pprof-enabled branch of StartServer,
// which registers the /debug/pprof handlers and logs the pprof notice.
func TestStartServer_WithPprof(t *testing.T) {
	t.Setenv("PODTRACE_METRICS_ADDR", "127.0.0.1:0")
	t.Setenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR", "1")
	t.Setenv("PODTRACE_METRICS_ENABLE_PPROF", "1")

	srv := StartServer()
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}
	defer srv.Shutdown()

	// Drive the registered pprof handler directly via the server's mux to
	// confirm the pprof routes were wired up without binding to a real port.
	mux, ok := srv.server.Handler.(*http.ServeMux)
	if !ok {
		t.Fatalf("expected server handler to be *http.ServeMux")
	}
	h, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if pattern == "" {
		t.Fatalf("expected /debug/pprof/ to be registered when pprof is enabled")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("expected pprof index to return 200, got %d", rr.Code)
	}
}
