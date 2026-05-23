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
	"github.com/podtrace/podtrace/internal/ebpf/probes"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// attachMetricsObserver bridges probes.AttachObserver into the
// per-program metric.
type attachMetricsObserver struct {
	metrics *Metrics
}

func (a *attachMetricsObserver) OnAttachFailure(program, symbol string, mandatory bool, err error) {
	if a == nil || a.metrics == nil {
		return
	}
	a.metrics.RecordProgramAttachFailure(program, tracer.ClassifyBackendError(err))
}

// Options configure a single agent run. Defaults are applied by
// DefaultOptions.
type Options struct {
	NodeName string

	SystemNamespace string

	TracerConfigName string

	MetricsAddr string
	HealthAddr  string

	StatusReportInterval time.Duration

	BackendFactory func() (tracer.TracerBackend, error)
}

// DefaultOptions returns production defaults.
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
		LeaderElection: false,
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
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		return fmt.Errorf("build manager: %w", err)
	}

	stats := newPerCRStats()
	enricher := NewPodEnricher()
	router := NewRouter(stats).WithEnricher(enricher)
	probeSrv := NewProbeServer(opts.HealthAddr, 0)
	metrics := NewMetrics()

	probes.SetAttachObserver(&attachMetricsObserver{metrics: metrics})

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
		Enricher:        enricher,
		CategoryGate:    makeCategoryGate(backend),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	writer := &StatusWriter{
		Client:     mgr.GetClient(),
		NodeName:   opts.NodeName,
		Interval:   opts.StatusReportInterval,
		Router:     router,
		Ready:      probeSrv.IsReady,
		Heartbeat:  probeSrv.Heartbeat,
		BackendErr: backendErr,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return mgr.Start(gctx) })
	g.Go(func() error { return engine.Run(gctx, targetsCh) })
	g.Go(func() error { return writer.Run(gctx) })
	g.Go(func() error { return probeSrv.Run(gctx) })
	g.Go(func() error { return serveMetrics(gctx, opts.MetricsAddr, metrics, logger) })

	g.Go(func() error {
		if !mgr.GetCache().WaitForCacheSync(gctx) {
			return errors.New("informer cache sync failed")
		}
		probeSrv.MarkReady()
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

// makeCategoryGate returns a closure suitable for
// AgentReconciler.CategoryGate.
func makeCategoryGate(backend tracer.TracerBackend) func(categories []string) error {
	if backend == nil {
		return nil
	}
	gate, ok := backend.(tracer.CategoryGateable)
	if !ok {
		return nil
	}
	return gate.SetEnabledCategories
}

// NoopBackend is the default TracerBackend when none is injected.
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
// channel.
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
