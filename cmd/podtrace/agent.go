package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/podtrace/podtrace/internal/agent"
	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

const (
	backendModeReal = "real"
	backendModeNoop = "noop"
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
	backendMode          string
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
	cmd.Flags().StringVar(&opts.backendMode, "backend", backendModeReal,
		"Tracer backend mode: 'real' loads the eBPF program (production); 'noop' skips kernel attachment and exercises only the control plane (dev/kind smoke tests)")

	return cmd
}

// toAgentOptions translates the Cobra flag struct into agent.Options
// and resolves $NODE_NAME / hostname fallbacks.
func toAgentOptions(c *agentOptions) (agent.Options, error) {
	node := c.nodeName
	if node == "" {
		node = agent.ResolveNodeName()
	}
	if node == "" {
		return agent.Options{}, errors.New("node name: set --node-name, export NODE_NAME, or run where /etc/hostname is readable")
	}
	factory, err := selectBackendFactory(c.backendMode)
	if err != nil {
		return agent.Options{}, err
	}
	return agent.Options{
		NodeName:             node,
		SystemNamespace:      c.systemNamespace,
		TracerConfigName:     c.tracerConfigName,
		MetricsAddr:          c.metricsAddr,
		HealthAddr:           c.healthAddr,
		StatusReportInterval: c.statusReportInterval,
		BackendFactory:       factory,
	}, nil
}

// selectBackendFactory returns the TracerBackend factory the CLI will
// inject into agent.Options.
func selectBackendFactory(mode string) (func() (tracer.TracerBackend, error), error) {
	switch mode {
	case backendModeReal, "":
		return agentBackendFactory, nil
	case backendModeNoop:
		return noopBackendFactory, nil
	default:
		return nil, fmt.Errorf("invalid --backend %q (must be %q or %q)", mode, backendModeReal, backendModeNoop)
	}
}

func agentBackendFactory() (tracer.TracerBackend, error) {
	tr, err := ebpf.NewTracer()
	if err != nil {
		return nil, err
	}
	return &ebpfBackendAdapter{tr: tr}, nil
}

// ebpfBackendAdapter narrows the internal eBPF tracer interface
// (path-list cgroup contract) to the pkg/tracer.TracerBackend contract
// (CgroupTarget snapshot).
type ebpfBackendAdapter struct {
	tr ebpf.TracerInterface
}

func (a *ebpfBackendAdapter) SetCgroups(targets []tracer.CgroupTarget) error {
	paths := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.CgroupPath == "" {
			continue
		}
		paths = append(paths, t.CgroupPath)
	}
	return a.tr.SetCgroups(paths)
}

func (a *ebpfBackendAdapter) AttachToCgroup(path string) error {
	return a.tr.AttachToCgroup(path)
}

func (a *ebpfBackendAdapter) SetContainerID(id string) error {
	return a.tr.SetContainerID(id)
}

func (a *ebpfBackendAdapter) Start(ctx context.Context, ch chan<- *events.Event) error {
	return a.tr.Start(ctx, ch)
}

func (a *ebpfBackendAdapter) Stop() error {
	return a.tr.Stop()
}

// SetEnabledCategories implements the optional pkg/tracer.CategoryGateable
// interface by delegating to the eBPF tracer's runtime probe-group gate.
func (a *ebpfBackendAdapter) SetEnabledCategories(categories []string) error {
	type categoryGateable interface {
		SetEnabledCategories([]string) error
	}
	g, ok := a.tr.(categoryGateable)
	if !ok {
		return nil
	}
	return g.SetEnabledCategories(categories)
}

func noopBackendFactory() (tracer.TracerBackend, error) {
	return agent.NewNoopBackend(), nil
}
