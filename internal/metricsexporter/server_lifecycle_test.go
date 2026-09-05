package metricsexporter

import (
	"net/http"
	"testing"
	"time"
)

func TestGaugeResetLoopStopsWhenTheServerStops(t *testing.T) {
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		gaugeResetLoop(stop, time.Millisecond)
	}()

	time.Sleep(20 * time.Millisecond)
	close(stop)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gaugeResetLoop outlived the server. A leaked ticker keeps clearing gauges on a " +
			"registry nothing serves, and every restarted server adds another")
	}
}

func TestStartServerWithPprofEnabledServesTheProfileEndpoints(t *testing.T) {
	t.Setenv("PODTRACE_METRICS_ENABLE_PPROF", "1")
	t.Setenv("PODTRACE_METRICS_ADDR", "127.0.0.1:0")

	srv := StartServer()
	if srv == nil {
		t.Fatal("StartServer returned nil")
	}
	defer srv.Shutdown()

	if srv.server.Handler == nil {
		t.Fatal("server has no handler")
	}
	request, err := http.NewRequest(http.MethodGet, "/debug/pprof/cmdline", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, pattern := srv.server.Handler.(*http.ServeMux).Handler(request); pattern == "" {
		t.Error("pprof was enabled but /debug/pprof/cmdline is not routed. The knob would read " +
			"as on while the endpoints stayed absent")
	}
}

func TestStartServerLogsRatherThanCrashingOnABusyPort(t *testing.T) {
	t.Setenv("PODTRACE_METRICS_ADDR", "127.0.0.1:9975")

	first := StartServer()
	defer first.Shutdown()
	time.Sleep(50 * time.Millisecond)

	second := StartServer()
	defer second.Shutdown()
	time.Sleep(150 * time.Millisecond)
}
