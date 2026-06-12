package main

import (
	"github.com/podtrace/podtrace/internal/config"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/podtrace/podtrace/internal/operator"
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
			// ctrl.SetupSignalHandler returns a ctx that cancels on
			// SIGTERM/SIGINT. It is also process-singleton, so we wire
			// it once here rather than pushing into internal/operator.
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

	return cmd
}

// toOperatorOptions is the sole translation point between the CLI flag
// struct and the operator package's Options struct. Keeping the CLI
// layer thin here lets internal/operator be a reusable library.
func toOperatorOptions(c *operatorOptions, leaderNSExplicit bool) operator.Options {
	// NODE_NAME / POD_NAMESPACE leak through for leader-elect-namespace
	// when the user wants "wherever this pod runs"; this first iteration
	// keeps the flag explicit.
	leaderNS := c.leaderElectNamespace
	if leaderNS == "" {
		leaderNS = c.systemNamespace
	}
	// If POD_NAMESPACE is set (common in in-cluster deployments) and the
	// user did not pass --leader-elect-namespace, prefer the pod's own NS.
	// Explicitness comes from cobra's Changed, NOT from comparing against
	// the default literal: an operator explicitly passing the default
	// value was silently overridden by the environment.
	if envNS, ok := os.LookupEnv("POD_NAMESPACE"); ok && !leaderNSExplicit {
		leaderNS = envNS
	}
	return operator.Options{
		SystemNamespace:         c.systemNamespace,
		MetricsBindAddress:      c.metricsAddr,
		HealthBindAddress:       c.healthAddr,
		LeaderElection:          c.leaderElect,
		LeaderElectionNamespace: leaderNS,
		WebhookPort:             c.webhookPort,
		WebhookCertDir:          c.webhookCertDir,
		BootstrapFallbackImage:  bootstrapFallbackImage(),
	}
}

// releaseVersionPattern matches clean release versions (v0.12.9 / 0.12.9) —
// dev builds (git describe suffixes, "dev", -dirty) must not produce a
// fallback image, since that tag does not exist in the registry and the
// bootstrap TracerConfig would render an unpullable agent DaemonSet.
var releaseVersionPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// bootstrapFallbackImage derives the agent image for the TracerConfig
// bootstrap from the operator binary's own build identity. It is the second
// line of defense behind the PODTRACE_BOOTSTRAP_IMAGE env var: distributions
// that forget the env (the OLM CSV did, leaving installs with no agent
// DaemonSet) still bootstrap correctly when running a release build.
func bootstrapFallbackImage() string {
	if config.Image == "" || !releaseVersionPattern.MatchString(config.Version) {
		return ""
	}
	return config.Image + ":" + strings.TrimPrefix(config.Version, "v")
}
