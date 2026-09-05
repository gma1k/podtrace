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
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/workloadmetrics"
	"github.com/gma1k/podtrace/pkg/tracer"
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

	RestConfig *rest.Config
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
	logger := ctrllog.Log.WithName("agent").
		WithValues("node", opts.NodeName, "tracerConfig", opts.TracerConfigName)

	if alertManager, mErr := alerting.NewManager(); mErr != nil {
		logger.Error(mErr, "failed to create alert manager; resource alerts disabled")
	} else if alertManager != nil {
		alerting.SetGlobalManager(alertManager)
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
			defer cancel()
			_ = alertManager.Shutdown(shutdownCtx)
		}()
		logger.Info("alert manager initialized", "enabled", alertManager.IsEnabled())
	}

	scheme, err := newAgentScheme()
	if err != nil {
		return err
	}

	restConfig := opts.RestConfig
	if restConfig == nil {
		restConfig = ctrl.GetConfigOrDie()
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:         scheme,
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
				&discoveryv1.EndpointSlice{}: {
					Transform: trimEndpointSlice,
				},
				&corev1.Service{}: {
					Transform: trimService,
				},
			},
		},
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		return fmt.Errorf("build manager: %w", err)
	}

	if config.AlertingEnabled && config.AlertEventsEnabled {
		if am := alerting.GetGlobalManager(); am != nil {
			am.EnsureEnabledWithSender(newAlertEventSender(mgr.GetClient()))
			logger.Info("kubernetes-event alert sink enabled (flight recorder trigger source)")
		}
	}

	stats := newPerCRStats()
	enricher := NewPodEnricher()
	router := NewRouter(stats).WithEnricher(enricher)
	probeSrv := NewProbeServer(opts.HealthAddr, 0)
	metrics := NewMetrics()
	metrics.SetIdentity(opts.NodeName, opts.TracerConfigName)

	probes.SetAttachObserver(&attachMetricsObserver{metrics: metrics})

	backend, backendErr := buildBackend(opts, logger)
	if backendErr != nil {
		reason := tracer.ClassifyBackendError(backendErr)
		logger.Error(backendErr, "tracer backend unavailable — running in degraded noop mode",
			"reason", reason)
		metrics.BackendDegraded.WithLabelValues(reason).Set(1)
		probeSrv.MarkDegraded(reason)
	}

	var peers *PeerResolver
	if config.WorkloadMetricsEnabled {
		if err := RegisterPeerIndex(ctx, mgr); err != nil {
			logger.Error(err, "service-map peer index unavailable; edges will not be recorded")
		} else {
			peers = NewPeerResolver(clusterPeerLookup(mgr.GetCache()))
		}
	}

	exporters, metricsSink, expErr := buildExporters(router, metrics, enricher, peers, logger)
	if expErr != nil {
		return expErr
	}
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
		MetricsPlane: MetricsPlaneConfig{
			Enabled:           config.WorkloadMetricsEnabled,
			ExcludeNamespaces: config.WorkloadMetricsExcludedNamespaces,
		},
		WorkloadMetrics: workloadMetricProducer(metricsSink),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	writer := &StatusWriter{
		Client:        mgr.GetClient(),
		NodeName:      opts.NodeName,
		Interval:      opts.StatusReportInterval,
		Router:        router,
		Ready:         probeSrv.IsReady,
		Heartbeat:     probeSrv.Heartbeat,
		KernelDropped: metrics.KernelDroppedTotal,
		BackendErr:    backendErr,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return mgr.Start(gctx) })
	g.Go(func() error { return engine.Run(gctx, targetsCh) })
	g.Go(func() error { return writer.Run(gctx) })
	g.Go(func() error { return probeSrv.Run(gctx) })
	g.Go(func() error { return serveMetrics(gctx, opts.MetricsAddr, metrics, logger) })
	g.Go(func() error { return reapWorkloadMetrics(gctx, metricsSink, logger) })

	g.Go(func() error {
		if err := cacheSyncError(mgr.GetCache().WaitForCacheSync(gctx), gctx.Err()); err != nil {
			return err
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

// cacheSyncError decides whether a cache that stopped syncing is a
// failure.
func cacheSyncError(synced bool, ctxErr error) error {
	if synced || ctxErr != nil {
		return nil
	}
	return errors.New("informer cache sync failed")
}

func (o *Options) validate() error {
	if o.NodeName == "" {
		return errors.New("agent: NodeName is required (set $NODE_NAME via downward API)")
	}
	if o.SystemNamespace == "" {
		return errors.New("agent: SystemNamespace is required")
	}
	if o.TracerConfigName == "" {
		o.TracerConfigName = "default"
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

func newMetricsServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
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
	srv := newMetricsServer(mux)
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

// workloadMetricProducer wraps the plane in the Prometheus-to-OTLP
// producer the metric pusher reads.
func workloadMetricProducer(sink *workloadmetrics.Sink) metricProducer {
	if sink == nil {
		return nil
	}
	return workloadmetrics.NewProducer(sink)
}

func peerLookup(r *PeerResolver) func(string, uint16) (workloadmetrics.PeerIdentity, bool) {
	if r == nil {
		return nil
	}
	return r.Resolve
}

// buildExporters assembles the engine's fan-out list.
func buildExporters(router *Router, metrics *Metrics, enricher *PodEnricher, peers *PeerResolver, logger logr.Logger) ([]tracer.Exporter, *workloadmetrics.Sink, error) {
	exporters := []tracer.Exporter{router}

	if !config.WorkloadMetricsEnabled {
		return exporters, nil, nil
	}

	sink, err := workloadmetrics.New(metrics.Registerer(), workloadmetrics.Options{
		SeriesBudget:         config.WorkloadMetricsBudget,
		NativeHistograms:     config.WorkloadMetricsNativeHistograms,
		IncludePodLabel:      config.WorkloadMetricsPodLabel,
		IncludeProcessLabel:  config.WorkloadMetricsProcessLabel,
		Lookup:               enricherLookup(enricher),
		ResolvePeer:          peerLookup(peers),
		SemanticConventions:  config.WorkloadMetricsSemanticConv,
		AttributeCardinality: config.WorkloadMetricsAttributeLimit,
		OnBudgetExhausted: func(budget int) {
			logger.Error(nil, "continuous metrics series budget exhausted; new series are being refused",
				"seriesBudget", budget,
				"remedy", "raise TracerConfig.spec.agent.metrics.seriesBudget or add excludeNamespaces",
				"metric", "podtrace_workload_metrics_series_dropped_total")
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build workload metrics plane: %w", err)
	}

	logger.Info("continuous workload metrics enabled",
		"seriesBudget", config.WorkloadMetricsBudget,
		"nativeHistograms", config.WorkloadMetricsNativeHistograms)
	return append(exporters, sink), sink, nil
}

// reapWorkloadMetrics periodically drops series whose workload stopped
// being observed, so the per-node budget is spent on what is running
// rather than on what used to run.
func reapWorkloadMetrics(ctx context.Context, sink *workloadmetrics.Sink, logger logr.Logger) error {
	if sink == nil {
		return nil
	}
	ticker := time.NewTicker(config.WorkloadMetricsReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if n := sink.Reap(config.WorkloadMetricsSeriesTTL); n > 0 {
				logger.V(1).Info("reaped idle workload metric series",
					"removed", n, "idleFor", config.WorkloadMetricsSeriesTTL)
			}
		}
	}
}

func enricherLookup(e *PodEnricher) func(uint64) (events.K8sMetadata, bool) {
	if e == nil {
		return nil
	}
	return e.Lookup
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
