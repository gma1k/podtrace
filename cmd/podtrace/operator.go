package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// operatorOptions holds flags for `podtrace operator`.
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
			return fmt.Errorf("operator mode is not available in this release")
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
	cmd.Flags().StringVar(&opts.webhookCertDir, "webhook-cert-dir", "/var/run/podtrace/tls",
		"Directory containing tls.crt and tls.key for the webhook server")

	return cmd
}
