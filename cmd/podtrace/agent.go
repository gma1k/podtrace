package main

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/podtrace/podtrace/internal/agent"
)

// agentOptions holds flags for `podtrace agent`. Defaults mirror
// agent.DefaultOptions; the toAgentOptions translation keeps the Cobra
// surface authoritative for flag names.
type agentOptions struct {
	systemNamespace      string
	tracerConfigName     string
	nodeName             string
	metricsAddr          string
	healthAddr           string
	statusReportInterval time.Duration
}

func newAgentCmd() *cobra.Command {
	opts := &agentOptions{}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run podtrace as a per-node agent driven by PodTrace CRDs (DaemonSet mode)",
		Long: `Agent mode runs podtrace as a long-lived per-node DaemonSet process that
watches PodTrace custom resources and feeds matching pods into the local
tracer. Multiple PodTrace CRs targeting the same node are merged into a
single tracer instance (one set of cgroups, union of filters, per-CR
exporter routing).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Signal handler is process-singleton; wired here so
			// internal/agent stays a reusable library.
			ctx := ctrl.SetupSignalHandler()
			resolved, err := toAgentOptions(opts)
			if err != nil {
				return err
			}
			return agent.Run(ctx, resolved)
		},
	}

	cmd.Flags().StringVar(&opts.systemNamespace, "system-namespace", "podtrace-system",
		"Namespace where exporter bundles live (maintained by the operator)")
	cmd.Flags().StringVar(&opts.tracerConfigName, "tracer-config", "default",
		"Name of the cluster-scoped TracerConfig resource to observe")
	cmd.Flags().StringVar(&opts.nodeName, "node-name", "",
		"Name of the node this agent runs on (defaults to $NODE_NAME or hostname)")
	cmd.Flags().StringVar(&opts.metricsAddr, "metrics-addr", ":9090",
		"Address for the Prometheus metrics endpoint")
	cmd.Flags().StringVar(&opts.healthAddr, "health-addr", ":9091",
		"Address for liveness/readiness probes")
	cmd.Flags().DurationVar(&opts.statusReportInterval, "status-report-interval", 0,
		"How often to patch PodTrace.status.nodeStatus (default: 30s)")

	return cmd
}

// toAgentOptions translates the Cobra flag struct into agent.Options
// and resolves $NODE_NAME / hostname fallbacks. Returns an error only
// when the node name cannot be determined, because the agent cannot
// function without knowing which node it is on.
func toAgentOptions(c *agentOptions) (agent.Options, error) {
	node := c.nodeName
	if node == "" {
		node = agent.ResolveNodeName()
	}
	if node == "" {
		return agent.Options{}, errors.New("node name: set --node-name, export NODE_NAME, or run where /etc/hostname is readable")
	}
	return agent.Options{
		NodeName:             node,
		SystemNamespace:      c.systemNamespace,
		TracerConfigName:     c.tracerConfigName,
		MetricsAddr:          c.metricsAddr,
		HealthAddr:           c.healthAddr,
		StatusReportInterval: c.statusReportInterval,
	}, nil
}
