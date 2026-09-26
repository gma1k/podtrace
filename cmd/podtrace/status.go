package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/gma1k/podtrace/internal/status"
)

const clearScreen = "\033[H\033[2J"

// statusPollInterval is how often --wait checks again; tests shorten it.
var statusPollInterval = 2 * time.Second

type statusOptions struct {
	Kubeconfig      string
	Context         string
	SystemNamespace string
	Namespace       string
	Workload        string
	Profile         string
	Output          string
	Top             int
	Window          time.Duration
	Watch           bool
	Interval        time.Duration
	Wait            bool
	WaitDuration    time.Duration
}

// statusClusterFactory builds the cluster the command reads; tests replace it.
var statusClusterFactory = func(opts statusOptions) (status.Cluster, error) {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		loader.ExplicitPath = opts.Kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader,
		&clientcmd.ConfigOverrides{CurrentContext: opts.Context}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	// Two proxied reads per agent in parallel would otherwise queue behind
	// client-go's default of five requests a second.
	cfg.QPS, cfg.Burst = 50, 100
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	return &status.KubeCluster{Client: cs, SystemNamespace: opts.SystemNamespace}, nil
}

// stdoutIsTerminal reports whether --watch can redraw in place.
var stdoutIsTerminal = func() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func newStatusCmd() *cobra.Command {
	opts := statusOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what the podtrace agents see: fleet health, active issues and the busiest workloads",
		Long: `Read every podtrace agent through the API server and show, in one place:

  - each node's agent and whether it is capturing,
  - the issues the continuous inspections have raised,
  - the workloads with the most trouble or traffic: requests per second,
    error rate and p95 latency over the last window,
  - with --profile, the hot functions of one workload.

It needs no metrics backend and no port-forward: only get on pods/proxy in the
podtrace system namespace, list on events for issue messages, and list on
deployments and daemonsets there to check the operator and the fleets.

The exit status is 0 when podtrace is healthy (operator available, every
fleet rolled out, every agent capturing) and 1 otherwise, so a script can act
on it. Active workload issues do not change it.`,
		Example: `  # The cluster at a glance:
  kubectl podtrace status

  # One namespace, refreshed every 10 seconds:
  kubectl podtrace status -n shop --watch

  # Where one workload spends its CPU:
  kubectl podtrace status --profile shop/checkout

  # After an install or upgrade, block until podtrace is healthy:
  kubectl podtrace status --wait

  # For scripts:
  kubectl podtrace status -o json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return runStatus(ctx, opts, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to a kubeconfig file (defaults to KUBECONFIG, then ~/.kube/config)")
	f.StringVar(&opts.Context, "context", "", "Kubeconfig context to use (defaults to the current context)")
	f.StringVar(&opts.SystemNamespace, "system-namespace", "podtrace-system", "Namespace the podtrace agents run in")
	f.StringVarP(&opts.Namespace, "namespace", "n", "", "Show only this namespace's workloads and issues (default: all namespaces)")
	f.StringVar(&opts.Workload, "workload", "", "Show only this workload")
	f.StringVar(&opts.Profile, "profile", "", "Also show the hot functions of one workload, as namespace/workload (or workload with -n)")
	f.StringVarP(&opts.Output, "output", "o", "table", "Output format: table or json")
	f.IntVar(&opts.Top, "top", 10, "How many workloads, and profile frames, to show")
	f.DurationVar(&opts.Window, "window", 10*time.Second, "How long to measure rates over before the first report")
	f.BoolVarP(&opts.Watch, "watch", "w", false, "Keep refreshing until interrupted")
	f.DurationVar(&opts.Interval, "interval", 10*time.Second, "Time between refreshes with --watch")
	f.BoolVar(&opts.Wait, "wait", false, "Wait until podtrace is healthy before reporting, and fail if it is not by --wait-duration")
	f.DurationVar(&opts.WaitDuration, "wait-duration", 5*time.Minute, "How long --wait waits")
	return cmd
}

// validate checks the flags and resolves --profile into namespace and workload.
func (o statusOptions) validate() (profileNamespace, profileWorkload string, err error) {
	switch o.Output {
	case "table", "json":
	default:
		return "", "", fmt.Errorf("--output must be table or json, not %q", o.Output)
	}
	if o.Top < 1 {
		return "", "", fmt.Errorf("--top must be at least 1")
	}
	if o.Window < time.Second {
		return "", "", fmt.Errorf("--window must be at least 1s: rates over less are mostly noise")
	}
	if o.Watch && o.Interval < time.Second {
		return "", "", fmt.Errorf("--interval must be at least 1s")
	}
	if o.Wait && o.WaitDuration < time.Second {
		return "", "", fmt.Errorf("--wait-duration must be at least 1s")
	}
	if o.SystemNamespace == "" {
		return "", "", fmt.Errorf("--system-namespace must not be empty")
	}
	if o.Profile == "" {
		return "", "", nil
	}
	if ns, wl, ok := strings.Cut(o.Profile, "/"); ok {
		if ns == "" || wl == "" || strings.Contains(wl, "/") {
			return "", "", fmt.Errorf("--profile must be namespace/workload, not %q", o.Profile)
		}
		return ns, wl, nil
	}
	if o.Namespace == "" {
		return "", "", fmt.Errorf("--profile %s needs a namespace: write it as namespace/%s or pass -n", o.Profile, o.Profile)
	}
	return o.Namespace, o.Profile, nil
}

// notHealthyError is the exit error when podtrace is not healthy. The report
// has already been printed; the message only says why the exit status is 1.
func notHealthyError(problems []string) error {
	return fmt.Errorf("podtrace is not healthy: %s", strings.Join(problems, "; "))
}

// waitHealthy polls until podtrace is healthy or wait runs out, writing a
// line to progress whenever what is wrong changes.
func waitHealthy(ctx context.Context, collector *status.Collector, wait time.Duration, progress io.Writer) error {
	deadline := time.Now().Add(wait)
	last := ""
	for {
		var now string
		report, err := collector.Health(ctx)
		switch {
		case err != nil:
			now = err.Error()
		case report.Healthy:
			_, _ = fmt.Fprintln(progress, "✓ podtrace is healthy")
			return nil
		default:
			now = progressLine(report.Problems)
		}
		if now != last {
			_, _ = fmt.Fprintf(progress, "… waiting: %s\n", now)
			last = now
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("podtrace was not healthy within %s", wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(statusPollInterval):
		}
	}
}

// progressLine is what --wait prints while waiting. On a large cluster a
// rollout leaves many agents not ready at once, so past a few they are
// counted rather than listed; the final report lists every one.
func progressLine(problems []string) string {
	const listed = 3
	var agents, others []string
	for _, p := range problems {
		if strings.HasPrefix(p, "agent on ") {
			agents = append(agents, p)
		} else {
			others = append(others, p)
		}
	}
	if len(agents) > listed {
		agents = append(agents[:listed:listed], fmt.Sprintf("and %d more agents", len(agents)-listed))
	}
	return strings.Join(append(others, agents...), "; ")
}

func runStatus(ctx context.Context, opts statusOptions, out, progress io.Writer) error {
	profileNamespace, profileWorkload, err := opts.validate()
	if err != nil {
		return err
	}
	cluster, err := statusClusterFactory(opts)
	if err != nil {
		return err
	}
	collector := &status.Collector{
		Cluster: cluster,
		Options: status.Options{Namespace: opts.Namespace, Workload: opts.Workload, Top: opts.Top},
		Window:  opts.Window,
	}
	redraw := opts.Watch && opts.Output == "table" && stdoutIsTerminal()

	if opts.Wait {
		if err := waitHealthy(ctx, collector, opts.WaitDuration, progress); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			_, _ = fmt.Fprintf(progress, "✗ %s; the report below shows what is still wrong\n", err)
		}
	}

	for {
		report, err := collector.Collect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if profileWorkload != "" {
			hot, failed, err := collector.Profile(ctx, profileNamespace, profileWorkload, opts.Top)
			if err != nil {
				return err
			}
			report.Profile = hot
			report.Warnings = append(report.Warnings, failed...)
			if hot == nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("no agent has a profile for %s/%s yet; "+
					"it appears once the workload has run on CPU with continuous profiling on",
					profileNamespace, profileWorkload))
			}
		}
		if err := render(out, report, opts, redraw); err != nil {
			return err
		}
		if !opts.Watch {
			if !report.Healthy {
				return notHealthyError(report.Problems)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.Interval):
		}
	}
}

func render(out io.Writer, report status.Report, opts statusOptions, redraw bool) error {
	if opts.Output == "json" {
		return status.RenderJSON(out, report, !opts.Watch)
	}
	switch {
	case redraw:
		if _, err := io.WriteString(out, clearScreen); err != nil {
			return err
		}
	case opts.Watch:
		if _, err := io.WriteString(out, "\n"+strings.Repeat("─", 60)+"\n"); err != nil {
			return err
		}
	}
	return status.RenderText(out, report)
}
