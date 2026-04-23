package operator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// Options configure a single operator run. All addresses default to
// loopback so unit tests can bring the manager up without opening public
// ports; production callers override via the CLI flags in
// cmd/podtrace/operator.go.
type Options struct {
	// SystemNamespace is the namespace in which the operator creates
	// the agent DaemonSet, agent RBAC, per-session Jobs, and resolved
	// exporter bundles. Must be a PSA-privileged namespace.
	SystemNamespace string

	// MetricsBindAddress (host:port) for controller-runtime's Prometheus
	// metrics endpoint. Empty disables the server.
	MetricsBindAddress string

	// HealthBindAddress (host:port) for /healthz and /readyz. Empty
	// disables the server.
	HealthBindAddress string

	// LeaderElection enables HA-safe single-writer reconciliation. Always
	// on in production; tests disable it because the envtest harness
	// tears the manager down too fast for a lease renewal.
	LeaderElection          bool
	LeaderElectionNamespace string
	LeaderElectionID        string

	// WebhookPort / WebhookCertDir wire the admission webhook server.
	// When WebhookCertDir is empty, the webhook server is not started —
	// useful when running the operator behind an external cert flow.
	WebhookPort    int
	WebhookCertDir string

	// SyncPeriod bounds how often controller-runtime re-lists informer
	// caches. Zero leaves the library default (10h).
	SyncPeriod time.Duration

	// GracefulShutdownTimeout caps how long Run will block after ctx is
	// cancelled. Zero leaves the library default.
	GracefulShutdownTimeout time.Duration
}

// DefaultOptions returns production-sensible defaults. Callers typically
// start from these and override only what the CLI flags customised.
func DefaultOptions() Options {
	return Options{
		SystemNamespace:         "podtrace-system",
		MetricsBindAddress:      ":8080",
		HealthBindAddress:       ":8081",
		LeaderElection:          true,
		LeaderElectionNamespace: "podtrace-system",
		LeaderElectionID:        "podtrace-operator.podtrace.io",
		WebhookPort:             9443,
		WebhookCertDir:          "/var/run/podtrace/tls",
	}
}

// NewScheme returns a scheme with both client-go's default types and
// the podtrace v1alpha1 API group registered. Exposed so tests can
// share one scheme across envtest harnesses.
func NewScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("clientgo scheme: %w", err)
	}
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("podtrace scheme: %w", err)
	}
	return s, nil
}

// Run boots a controller-runtime manager, wires all three reconcilers and
// the validating webhook, and blocks until ctx is cancelled. Returns the
// first terminal error, or nil on clean shutdown.
//
// The shape mirrors what `cmd/podtrace operator` wants: one function
// call that owns the whole control-plane lifetime.
func Run(ctx context.Context, opts Options) error {
	if opts.SystemNamespace == "" {
		return errors.New("operator: SystemNamespace is required")
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))

	scheme, err := NewScheme()
	if err != nil {
		return err
	}

	managerOpts := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: opts.MetricsBindAddress,
		},
		HealthProbeBindAddress:  opts.HealthBindAddress,
		LeaderElection:          opts.LeaderElection,
		LeaderElectionID:        leaderElectionID(opts),
		LeaderElectionNamespace: opts.LeaderElectionNamespace,
	}
	if opts.GracefulShutdownTimeout > 0 {
		managerOpts.GracefulShutdownTimeout = &opts.GracefulShutdownTimeout
	}
	if opts.WebhookCertDir != "" {
		managerOpts.WebhookServer = webhook.NewServer(webhook.Options{
			Port:    opts.WebhookPort,
			CertDir: opts.WebhookCertDir,
		})
	}
	if opts.SyncPeriod > 0 {
		managerOpts.Cache.SyncPeriod = &opts.SyncPeriod
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOpts)
	if err != nil {
		return fmt.Errorf("build manager: %w", err)
	}

	if err := registerReconcilers(mgr, opts); err != nil {
		return fmt.Errorf("register reconcilers: %w", err)
	}

	if opts.WebhookCertDir != "" {
		if err := registerWebhooks(mgr); err != nil {
			return fmt.Errorf("register webhooks: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz: %w", err)
	}

	utilruntime.Must(nil) // keep utilruntime import referenced without panicking
	return mgr.Start(ctx)
}

func leaderElectionID(opts Options) string {
	if opts.LeaderElectionID != "" {
		return opts.LeaderElectionID
	}
	return "podtrace-operator.podtrace.io"
}

// registerWebhooks wires the three validating webhooks onto the manager.
// Each Setup* function declares a +kubebuilder:webhook marker so the
// paths match the Helm-rendered ValidatingWebhookConfiguration.
func registerWebhooks(mgr ctrl.Manager) error {
	if err := podtracev1alpha1.SetupPodTraceWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("podtrace webhook: %w", err)
	}
	if err := podtracev1alpha1.SetupPodTraceSessionWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("podtracesession webhook: %w", err)
	}
	if err := podtracev1alpha1.SetupExporterConfigWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("exporterconfig webhook: %w", err)
	}
	return nil
}
