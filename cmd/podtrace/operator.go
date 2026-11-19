package main

import (
	"os"
	"regexp"
	"strings"

	"github.com/gma1k/podtrace/internal/config"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/gma1k/podtrace/internal/operator"
)

// operatorOptions holds flags for `podtrace operator`. Defaults mirror
// operator.DefaultOptions(); the two layers are kept in sync by the
// toOperatorOptions translation below, so the Cobra surface remains the
// single source of truth for flag names.
type operatorOptions struct {
	systemNamespace      string
	metricsAddr          string
	healthAddr           string
	leaderElect          bool
	leaderElectNamespace string
	webhookPort          int
	webhookCertDir       string
	webhookManageCerts   bool
	webhookSecretName    string
	webhookServiceName   string
	webhookConfigName    string
}

func newOperatorCmd() *cobra.Command {
	opts := &operatorOptions{}

	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Run the podtrace Kubernetes operator (Deployment mode)",
		Long: `Operator mode runs the controller-runtime manager that reconciles
podtrace's CustomResourceDefinitions:

  TracerConfig     cluster-wide infrastructure: agent DaemonSet, image, resources
  ExporterConfig   reusable exporter referenced by traces
  PodTrace         continuous realtime tracing over a dynamic pod set
  PodTraceSession  bounded diagnose-mode trace (operator spawns per-node Jobs)

The operator runs unprivileged. Only the agent DaemonSet and per-session
Jobs require privileged pods, and they live in the podtrace-system
namespace.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := ctrl.SetupSignalHandler()
			leaderNSExplicit := cmd.Flags().Changed("leader-elect-namespace")
			return operator.Run(ctx, toOperatorOptions(opts, leaderNSExplicit))
		},
	}

	cmd.Flags().StringVar(&opts.systemNamespace, "system-namespace", "podtrace-system",
		"Namespace for the agent DaemonSet, session Jobs, and resolved exporter bundles")
	cmd.Flags().StringVar(&opts.metricsAddr, "metrics-addr", ":8080",
		"Address for the Prometheus metrics endpoint")
	cmd.Flags().StringVar(&opts.healthAddr, "health-addr", ":8081",
		"Address for liveness/readiness probes")
	cmd.Flags().BoolVar(&opts.leaderElect, "leader-elect", true,
		"Enable leader election (required for HA deployments)")
	cmd.Flags().StringVar(&opts.leaderElectNamespace, "leader-elect-namespace", "podtrace-system",
		"Namespace holding the leader-election lease")
	cmd.Flags().IntVar(&opts.webhookPort, "webhook-port", 9443,
		"Port the validating webhook server listens on")
	cmd.Flags().StringVar(&opts.webhookCertDir, "webhook-cert-dir", "",
		"Directory containing tls.crt and tls.key for the webhook server (empty disables the webhook)")
	cmd.Flags().BoolVar(&opts.webhookManageCerts, "webhook-manage-certs", false,
		"Issue and renew the webhook certificate in the operator, writing it to --webhook-cert-dir, instead of reading one from cert-manager or a Secret")
	cmd.Flags().StringVar(&opts.webhookSecretName, "webhook-cert-secret", "podtrace-webhook-certs",
		"Secret in --system-namespace that holds the operator-managed webhook CA and certificate")
	cmd.Flags().StringVar(&opts.webhookServiceName, "webhook-service", "podtrace-webhook",
		"Service the API server reaches the webhook through; its DNS names go into the certificate")
	cmd.Flags().StringVar(&opts.webhookConfigName, "webhook-configuration", "podtrace-validating-webhook",
		"ValidatingWebhookConfiguration whose caBundle the operator keeps current")

	return cmd
}

// toOperatorOptions is the sole translation point between the CLI flag
// struct and the operator package's Options struct. Keeping the CLI
// layer thin here lets internal/operator be a reusable library.
func toOperatorOptions(c *operatorOptions, leaderNSExplicit bool) operator.Options {
	leaderNS := c.leaderElectNamespace
	if leaderNS == "" {
		leaderNS = c.systemNamespace
	}
	if envNS, ok := os.LookupEnv("POD_NAMESPACE"); ok && !leaderNSExplicit {
		leaderNS = envNS
	}
	var webhookCerts *operator.WebhookCertificateOptions
	if c.webhookManageCerts {
		webhookCerts = &operator.WebhookCertificateOptions{
			SecretName:               c.webhookSecretName,
			ServiceName:              c.webhookServiceName,
			WebhookConfigurationName: c.webhookConfigName,
		}
	}
	return operator.Options{
		SystemNamespace:           c.systemNamespace,
		MetricsBindAddress:        c.metricsAddr,
		HealthBindAddress:         c.healthAddr,
		LeaderElection:            c.leaderElect,
		LeaderElectionNamespace:   leaderNS,
		WebhookPort:               c.webhookPort,
		WebhookCertDir:            c.webhookCertDir,
		WebhookCertificates:       webhookCerts,
		BootstrapFallbackImage:    bootstrapFallbackImage(),
		BootstrapTracerConfigName: os.Getenv("PODTRACE_BOOTSTRAP_TC_NAME"),
	}
}

var releaseVersionPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// bootstrapFallbackImage derives the agent image for the TracerConfig
// bootstrap from the operator binary's own build identity.
func bootstrapFallbackImage() string {
	if config.Image == "" || !releaseVersionPattern.MatchString(config.Version) {
		return ""
	}
	return config.Image + ":" + strings.TrimPrefix(config.Version, "v")
}
