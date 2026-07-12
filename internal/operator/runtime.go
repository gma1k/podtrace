package operator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/podtrace/podtrace/internal/webhook/v1alpha1"
)

type Options struct {
	SystemNamespace string

	// MetricsBindAddress (host:port) for controller-runtime's Prometheus
	// metrics endpoint. Empty disables the server.
	MetricsBindAddress string

	HealthBindAddress string

	LeaderElection          bool
	LeaderElectionNamespace string
	LeaderElectionID        string

	WebhookPort    int
	WebhookCertDir string

	SyncPeriod time.Duration

	GracefulShutdownTimeout time.Duration

	BootstrapFallbackImage string

	BootstrapTracerConfigName string
}

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
// the podtrace v1alpha1 API group registered.
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

	if err := mgr.Add(&BootstrapDefaultTracerConfig{
		Client:           mgr.GetClient(),
		SystemNamespace:  opts.SystemNamespace,
		FallbackImage:    opts.BootstrapFallbackImage,
		TracerConfigName: opts.BootstrapTracerConfigName,
	}); err != nil {
		return fmt.Errorf("register TracerConfig bootstrap: %w", err)
	}

	return mgr.Start(ctx)
}

func leaderElectionID(opts Options) string {
	if opts.LeaderElectionID != "" {
		return opts.LeaderElectionID
	}
	return "podtrace-operator.podtrace.io"
}

// registerWebhooks wires the three validating webhooks onto the manager.
func registerWebhooks(mgr ctrl.Manager) error {
	if err := webhookv1alpha1.SetupPodTraceWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("podtrace webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupPodTraceSessionWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("podtracesession webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupExporterConfigWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("exporterconfig webhook: %w", err)
	}
	if err := webhookv1alpha1.SetupPodTraceScheduleWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("podtraceschedule webhook: %w", err)
	}
	return nil
}
