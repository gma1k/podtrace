package agent

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ProbeServer exposes /healthz and /readyz on a dedicated port so a
// Kubernetes kubelet can monitor the agent without having to read the
// shared /metrics surface.
//
//   - /healthz is a tripwire: "the agent process is up and its
//     reconcile loop has not stalled". Returns 200 while the writer
//     updates a liveness timestamp within the grace window.
//   - /readyz is stricter: "the agent is ready to route events". This
//     flips true only after the initial informer sync + tracer attach
//     have completed; returns 503 before then.
//
// The two are wired separately so slow initial sync does not get the
// DaemonSet pod killed by the liveness probe.
type ProbeServer struct {
	Addr string

	lastHeartbeat atomic.Int64 // UnixNano; updated by Heartbeat()
	readyFlag     atomic.Bool  // set by MarkReady()
	stall         time.Duration
}

// NewProbeServer returns a ProbeServer ready to serve /healthz and
// /readyz at addr. The stall value controls how long between
// Heartbeat() calls before /healthz flips to 503 (the reconcile loop
// should call Heartbeat on every tick — a stall indicates a hang).
func NewProbeServer(addr string, stallWindow time.Duration) *ProbeServer {
	if stallWindow <= 0 {
		stallWindow = 90 * time.Second
	}
	s := &ProbeServer{Addr: addr, stall: stallWindow}
	s.Heartbeat()
	return s
}

// Heartbeat records a liveness tick. Called by the status writer
// (which already runs periodically) so we do not need an extra
// goroutine just for probe freshness.
func (s *ProbeServer) Heartbeat() {
	s.lastHeartbeat.Store(time.Now().UnixNano())
}

// MarkReady toggles /readyz to 200. Called once informers have synced
// and the tracer is attached.
func (s *ProbeServer) MarkReady() { s.readyFlag.Store(true) }

// MarkUnready is used during shutdown to drain traffic before the pod
// terminates. Kubernetes's pre-stop hook can call this via an HTTP
// endpoint if we choose to expose one later.
func (s *ProbeServer) MarkUnready() { s.readyFlag.Store(false) }

// IsReady is exported so other goroutines (e.g. the status writer
// Ready callback) share the same truth.
func (s *ProbeServer) IsReady() bool { return s.readyFlag.Load() }

// Run serves the probe endpoints until ctx is done. Returns nil on
// graceful shutdown, otherwise the terminal error from http.ListenAndServe.
func (s *ProbeServer) Run(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("probes").WithValues("addr", s.Addr)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		// WithoutCancel gives us a fresh context that inherits values
		// (deadlines, tracing keys) from the original ctx without
		// carrying its "Done" signal. We need the freshness because
		// ctx just fired Done — graceful shutdown needs a positive
		// timeout, not an already-cancelled context.
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	logger.Info("starting probe server")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-shutdownDone
	return nil
}

func (s *ProbeServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	last := time.Unix(0, s.lastHeartbeat.Load())
	if time.Since(last) > s.stall {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("stalled"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *ProbeServer) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !s.readyFlag.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
