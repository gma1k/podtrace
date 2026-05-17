package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// Options configure a single agent run. Defaults are applied by
// DefaultOptions; callers override only what the CLI flags customised.
type Options struct {
	// NodeName is the node this agent runs on. Required — comes from
	// $NODE_NAME via the DaemonSet's downward API.
	NodeName string

	// SystemNamespace is where exporter bundles live (and where
	// podtrace-system resources are reconciled by the operator).
	SystemNamespace string

	// TracerConfigName lets the agent read infra defaults (currently
	// unused; reserved for bundle cache invalidation policies).
	TracerConfigName string

	MetricsAddr string
	HealthAddr  string

	// StatusReportInterval overrides the default 30s cadence. Tests set
	// this short; production leaves it at zero for the default.
	StatusReportInterval time.Duration

	// BackendFactory produces the TracerBackend the Engine will drive.
	// When nil, the agent falls back to a noop backend and logs a
	// one-line warning: the DaemonSet pod stays Ready so operators can
	// inspect it via kubectl, but no kernel-space tracing happens.
	// Tests inject a fake backend through this hook.
	BackendFactory func() (tracer.TracerBackend, error)
}

// DefaultOptions returns production defaults. NodeName and
// SystemNamespace are NOT defaulted because they have no reasonable
// static value — the CLI validates both.
func DefaultOptions() Options {
	return Options{
		MetricsAddr: ":9090",
		HealthAddr:  ":9091",
	}
}

// Run boots the per-node agent and blocks until ctx is cancelled.
// Returns nil on clean shutdown, otherwise the first terminal error.
func Run(ctx context.Context, opts Options) error {
	if err := opts.validate(); err != nil {
		return err
	}
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	logger := ctrllog.Log.WithName("agent").WithValues("node", opts.NodeName)

	scheme, err := newAgentScheme()
	if err != nil {
		return err
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		// LeaderElection OFF: each agent acts on its own node only, no
		// coordination needed across DaemonSet replicas.
		LeaderElection: false,
		// Pod cache is filtered to this node; the bundle ConfigMap/Secret
		// caches are filtered to the system namespace. PodTrace is
		// watched cluster-wide — that's the cross-namespace resource we
		// cannot narrow.
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {
					Field: fields.OneTermEqualSelector("spec.nodeName", opts.NodeName),
				},
				&corev1.ConfigMap{}: {
					Namespaces: map[string]cache.Config{opts.SystemNamespace: {}},
				},
				&corev1.Secret{}: {
					Namespaces: map[string]cache.Config{opts.SystemNamespace: {}},
				},
			},
		},
		// Metrics are served on the agent's own registry (not
		// controller-runtime's default) so the Prometheus scrape
		// surface is deterministic — see Metrics.NewMetrics.
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		return fmt.Errorf("build manager: %w", err)
	}

	stats := newPerCRStats()
	router := NewRouter(stats)
	probes := NewProbeServer(opts.HealthAddr, 0)
	metrics := NewMetrics()

	backend, backendErr := buildBackend(opts, logger)
	if backendErr != nil {
		reason := tracer.ClassifyBackendError(backendErr)
		logger.Error(backendErr, "tracer backend unavailable — running in degraded noop mode",
			"reason", reason)
		metrics.BackendDegraded.WithLabelValues(reason).Set(1)
	}

	exporters := []tracer.Exporter{router}
	engine, err := tracer.NewEngine(backend, exporters, tracer.Config{
		Observer: metrics.EngineObserver(),
	})
	if err != nil {
		return fmt.Errorf("build tracer engine: %w", err)
	}

	targetsCh := make(chan tracer.TargetSet, 8)

	reconciler := &AgentReconciler{
		Client:          mgr.GetClient(),
		NodeName:        opts.NodeName,
		SystemNamespace: opts.SystemNamespace,
		Router:          router,
		TargetsCh:       targetsCh,
		Metrics:         metrics,
		ExporterBuilder: BuildExporter,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	writer := &StatusWriter{
		Client:     mgr.GetClient(),
		NodeName:   opts.NodeName,
		Interval:   opts.StatusReportInterval,
		Router:     router,
		Ready:      probes.IsReady,
		Heartbeat:  probes.Heartbeat,
		BackendErr: backendErr,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return mgr.Start(gctx) })
	g.Go(func() error { return engine.Run(gctx, targetsCh) })
	g.Go(func() error { return writer.Run(gctx) })
	g.Go(func() error { return probes.Run(gctx) })
	g.Go(func() error { return serveMetrics(gctx, opts.MetricsAddr, metrics, logger) })

	// Mark ready once informers have synced — the manager's cache
	// Start is async, so we wait here. Until then /readyz returns 503.
	g.Go(func() error {
		if !mgr.GetCache().WaitForCacheSync(gctx) {
			return errors.New("informer cache sync failed")
		}
		probes.MarkReady()
		logger.Info("agent ready")
		return nil
	})

	err = g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (o Options) validate() error {
	if o.NodeName == "" {
		return errors.New("agent: NodeName is required (set $NODE_NAME via downward API)")
	}
	if o.SystemNamespace == "" {
		return errors.New("agent: SystemNamespace is required")
	}
	return nil
}

func newAgentScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(podtracev1alpha1.AddToScheme(s))
	return s, nil
}

// buildBackend returns the TracerBackend for the agent.
//
// Production: the CLI always sets BackendFactory (see cmd/podtrace/agent.go
// where the --backend flag selects between the real eBPF tracer and an
// explicit noop). A non-nil factory that returns an error is NOT fatal:
// the agent falls back to the noop backend so the pod stays Ready, the
// underlying error surfaces on PodTrace.status.nodeStatus.message via
// StatusWriter.BackendErr, and `kubectl describe pod` keeps showing the
// real cause. CrashLoopBackOff would hide that.
func buildBackend(opts Options, logger logr.Logger) (tracer.TracerBackend, error) {
	if opts.BackendFactory == nil {
		logger.Info("no BackendFactory supplied — using noop backend (library/test mode; production binaries always set this)")
		return newNoopBackend(), nil
	}
	backend, err := opts.BackendFactory()
	if err != nil {
		return newNoopBackend(), err
	}
	logger.Info("tracer backend ready", "backend", fmt.Sprintf("%T", backend))
	return backend, nil
}

// serveMetrics exposes the agent's Prometheus registry on the
// metrics-addr port. Short-circuit when the address is empty — useful
// in tests.
func serveMetrics(ctx context.Context, addr string, metrics *Metrics, logger logr.Logger) error {
	if addr == "" || addr == "0" {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	logger.Info("starting metrics server", "addr", addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// NoopBackend is the default TracerBackend when none is injected. It
// accepts every Attach/SetContainerID call and never produces events,
// so the agent's routing + status machinery is exercised end-to-end
// without requiring a privileged eBPF load.
type NoopBackend struct {
	mu       sync.Mutex
	eventCh  chan<- *events.Event
	attached map[string]struct{}
}

func newNoopBackend() *NoopBackend {
	return &NoopBackend{attached: map[string]struct{}{}}
}

func NewNoopBackend() *NoopBackend {
	return newNoopBackend()
}

func (b *NoopBackend) AttachToCgroup(path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attached[path] = struct{}{}
	return nil
}

func (b *NoopBackend) SetCgroups(targets []tracer.CgroupTarget) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attached = make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if t.CgroupPath == "" {
			continue
		}
		b.attached[t.CgroupPath] = struct{}{}
	}
	return nil
}

func (b *NoopBackend) SetContainerID(_ string) error { return nil }

func (b *NoopBackend) Start(_ context.Context, ch chan<- *events.Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eventCh = ch
	return nil
}

func (b *NoopBackend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eventCh = nil
	return nil
}

// Inject lets tests push synthetic events through the backend's
// channel. Returns false if Start has not yet been called.
func (b *NoopBackend) Inject(ev *events.Event) bool {
	b.mu.Lock()
	ch := b.eventCh
	b.mu.Unlock()
	if ch == nil {
		return false
	}
	ch <- ev
	return true
}

func ResolveNodeName() string {
	if n := strings.TrimSpace(os.Getenv("NODE_NAME")); n != "" {
		return n
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return ""
}
