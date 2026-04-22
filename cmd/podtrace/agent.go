package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// agentOptions holds flags for `podtrace agent`.
type agentOptions struct {
	systemNamespace  string
	tracerConfigName string
	nodeName         string
	metricsAddr      string
	healthAddr       string
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("agent mode is not available in this release")
		},
	}

	cmd.Flags().StringVar(&opts.systemNamespace, "system-namespace", "podtrace-system",
		"Namespace where the agent lives and reads its exporter bundles from")
	cmd.Flags().StringVar(&opts.tracerConfigName, "tracer-config", "default",
		"Name of the cluster-scoped TracerConfig resource to observe")
	cmd.Flags().StringVar(&opts.nodeName, "node-name", "",
		"Name of the node this agent runs on (defaults to $NODE_NAME)")
	cmd.Flags().StringVar(&opts.metricsAddr, "metrics-addr", ":9090",
		"Address for the Prometheus metrics endpoint")
	cmd.Flags().StringVar(&opts.healthAddr, "health-addr", ":9091",
		"Address for liveness/readiness probes")

	return cmd
}
