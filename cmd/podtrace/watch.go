package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/operator"
	"github.com/podtrace/podtrace/internal/validation"
)

// appNameLabel is the Kubernetes-recommended label that --app targets.
// --label is the escape hatch for any other labelling scheme.
const appNameLabel = "app.kubernetes.io/name"

var (
	watchAppName           string
	watchLabel             string
	watchAllNamespaces     bool
	watchNamespaceSelector string
	watchExporter          string
	watchName              string
	watchSample            int
	watchKubeconfig        string
	watchPrintOnly         bool
)

// registerTargetFlags binds the application/label targeting flags.
func registerTargetFlags(fs *pflag.FlagSet) {
	fs.StringVar(&watchAppName, "app", "", "Target an application by name; shorthand for --label "+appNameLabel+"=<NAME>.")
	fs.StringVar(&watchLabel, "label", "", "Label selector for target pods (e.g. app=api,tier=web). Mutually exclusive with --app.")
	fs.BoolVar(&watchAllNamespaces, "all-namespaces", false, "Match pods in every namespace (default: only --namespace).")
}

// registerWatchOnlyFlags binds the flags that only make sense for the managed
// `watch` subcommand.
func registerWatchOnlyFlags(fs *pflag.FlagSet) {
	fs.StringVar(&watchNamespaceSelector, "namespace-selector", "", "Only match namespaces carrying these labels (e.g. team=payments). Mutually exclusive with --all-namespaces.")
	fs.StringVar(&watchExporter, "exporter", "default", "Name of the ExporterConfig (in the PodTrace's namespace) events are sent to.")
	fs.StringVar(&watchName, "name", "", "Name for the created PodTrace (defaults to the --app value).")
	fs.IntVar(&watchSample, "sample", -1, "Sample percentage 0-100 (default: unset, i.e. the exporter's own default).")
	fs.StringVar(&watchKubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to a kubeconfig file (defaults to KUBECONFIG, then ~/.kube/config).")
	fs.BoolVar(&watchPrintOnly, "print-only", false, "Print the rendered PodTrace YAML instead of creating it.")
}

// newWatchCmd produces the `podtrace watch` subcommand. It is the canonical
// surface for managed, continuous, cluster-wide application tracing; the
// equivalent flags on the root command delegate to runWatch as well.
func newWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Create a managed PodTrace that continuously traces an application",
		Long: `Create a PodTrace custom resource that the operator and per-node agents
keep tracing continuously — across all matching namespaces and nodes, surviving
pod restarts and rollouts — until you delete it.

Unlike the default 'podtrace <pod>' command (which attaches eBPF ephemerally and
streams to your terminal), 'watch' is fire-and-forget: it creates the PodTrace and
exits. Events flow to the referenced ExporterConfig, not to this terminal.`,
		Example: `  # Trace an application everywhere, 24/7:
  podtrace watch --app checkout --all-namespaces --exporter otlp-default

  # Arbitrary label selector, scoped to one namespace:
  podtrace watch --label app=api,tier=web -n production --exporter otlp-default

  # Render the manifest without applying it:
  podtrace watch --app checkout --all-namespaces --print-only`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if !cmd.Flags().Changed("namespace") {
				if ctxNamespace, ok := kubernetes.NamespaceFromContext(); ok {
					namespace = ctxNamespace
				}
			}
			return runWatch(ctx, watchOptionsFromFlags())
		},
	}
	registerTargetFlags(cmd.Flags())
	registerWatchOnlyFlags(cmd.Flags())
	cmd.Flags().StringVarP(&namespace, "namespace", "n", config.DefaultNamespace, "Namespace to create the PodTrace in (its ExporterConfig must live here too; defaults to the current kubeconfig context's namespace)")
	cmd.Flags().StringVar(&eventFilter, "filter", "", "Event categories to capture (dns,net,fs,cpu,proc); empty = all")
	return cmd
}

// watchOptions is the resolved input to runWatch/buildPodTrace. Splitting it
// from the flag vars keeps buildPodTrace a pure, unit-testable function.
type watchOptions struct {
	AppName           string
	Label             string
	AllNamespaces     bool
	NamespaceSelector string
	Namespace         string
	Exporter          string
	Name              string
	Filter            string
	SamplePercent     int
	Kubeconfig        string
	PrintOnly         bool
}

func watchOptionsFromFlags() watchOptions {
	return watchOptions{
		AppName:           strings.TrimSpace(watchAppName),
		Label:             strings.TrimSpace(watchLabel),
		AllNamespaces:     watchAllNamespaces,
		NamespaceSelector: strings.TrimSpace(watchNamespaceSelector),
		Namespace:         namespace,
		Exporter:          strings.TrimSpace(watchExporter),
		Name:              strings.TrimSpace(watchName),
		Filter:            eventFilter,
		SamplePercent:     watchSample,
		Kubeconfig:        watchKubeconfig,
		PrintOnly:         watchPrintOnly,
	}
}

// runWatch builds the PodTrace from opts and either prints it (--print-only)
// or creates it in the cluster after verifying the referenced ExporterConfig
// exists. Client wiring mirrors `schedule trigger` (cmd/podtrace/schedule.go).
func runWatch(ctx context.Context, opts watchOptions) error {
	pt, err := buildPodTrace(opts)
	if err != nil {
		return err
	}

	if opts.PrintOnly {
		out, err := marshalPodTraceYAML(pt)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(out)
		return err
	}

	scheme, err := operator.NewScheme()
	if err != nil {
		return fmt.Errorf("build scheme: %w", err)
	}

	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		loader.ExplicitPath = opts.Kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	var ec podtracev1alpha1.ExporterConfig
	if err := c.Get(ctx, types.NamespacedName{Namespace: opts.Namespace, Name: opts.Exporter}, &ec); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf(
				"ExporterConfig %q not found in namespace %q.\n\n"+
					"podtrace watch needs an ExporterConfig to send events to. Either:\n"+
					"  • point at an existing one:  --exporter <name>\n"+
					"      (list them with: kubectl get exporterconfig -n %s)\n"+
					"  • or create one, e.g.:\n"+
					"      kubectl apply -n %s -f - <<'EOF'\n"+
					"      apiVersion: podtrace.io/v1alpha1\n"+
					"      kind: ExporterConfig\n"+
					"      metadata:\n"+
					"        name: %s\n"+
					"      spec:\n"+
					"        type: otlp\n"+
					"        otlp:\n"+
					"          endpoint: otel-collector:4317\n"+
					"      EOF",
				opts.Exporter, opts.Namespace, opts.Namespace, opts.Namespace, opts.Exporter)
		}
		return fmt.Errorf("check ExporterConfig %s/%s: %w", opts.Namespace, opts.Exporter, err)
	}

	if err := c.Create(ctx, pt); err != nil {
		return fmt.Errorf("create PodTrace: %w", err)
	}
	if _, err := fmt.Fprintf(os.Stdout, "podtrace.io/PodTrace %q created in namespace %q\n", pt.Name, pt.Namespace); err != nil {
		return fmt.Errorf("write confirmation to stdout: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "watch status with: kubectl get podtrace %s -n %s -w\n", pt.Name, pt.Namespace)
	return nil
}

// buildPodTrace renders a PodTrace from opts. It is pure (no cluster access)
// so the unit tests can exercise selector/namespace/name/filter construction
// directly, mirroring buildManualSession in schedule.go.
func buildPodTrace(opts watchOptions) (*podtracev1alpha1.PodTrace, error) {
	if opts.AppName == "" && opts.Label == "" {
		return nil, errors.New("one of --app or --label is required")
	}
	if opts.AppName != "" && opts.Label != "" {
		return nil, errors.New("--app and --label are mutually exclusive")
	}
	if opts.AllNamespaces && opts.NamespaceSelector != "" {
		return nil, errors.New("--all-namespaces and --namespace-selector are mutually exclusive")
	}
	if opts.Exporter == "" {
		return nil, errors.New("--exporter must not be empty")
	}
	if err := validation.ValidateNamespace(opts.Namespace); err != nil {
		return nil, fmt.Errorf("invalid namespace: %w", err)
	}

	var selector *metav1.LabelSelector
	if opts.AppName != "" {
		selector = &metav1.LabelSelector{MatchLabels: map[string]string{appNameLabel: opts.AppName}}
	} else {
		sel, err := metav1.ParseToLabelSelector(opts.Label)
		if err != nil {
			return nil, fmt.Errorf("invalid --label selector %q: %w", opts.Label, err)
		}
		selector = sel
	}

	var nsSelector *metav1.LabelSelector
	switch {
	case opts.AllNamespaces:
		nsSelector = &metav1.LabelSelector{}
	case opts.NamespaceSelector != "":
		sel, err := metav1.ParseToLabelSelector(opts.NamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid --namespace-selector %q: %w", opts.NamespaceSelector, err)
		}
		nsSelector = sel
	}

	name, err := deriveWatchName(opts)
	if err != nil {
		return nil, err
	}

	var filters []podtracev1alpha1.EventFilter
	if opts.Filter != "" {
		if err := validation.ValidateEventFilter(opts.Filter); err != nil {
			return nil, err
		}
		for _, f := range parseCSV(strings.ToLower(opts.Filter)) {
			filters = append(filters, podtracev1alpha1.EventFilter(f))
		}
	}

	var samplePercent *int32
	if opts.SamplePercent >= 0 {
		if opts.SamplePercent > 100 {
			return nil, fmt.Errorf("--sample must be between 0 and 100, got %d", opts.SamplePercent)
		}
		v := int32(opts.SamplePercent)
		samplePercent = &v
	}

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: opts.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "podtrace-cli",
			},
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:          selector,
			NamespaceSelector: nsSelector,
			Filters:           filters,
			ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: opts.Exporter},
			SamplePercent:     samplePercent,
		},
	}
	return pt, nil
}

// deriveWatchName resolves the PodTrace object name: explicit --name wins,
// otherwise the --app value is used. --label alone has no natural name, so it
// requires --name. The result must be a valid RFC-1123 DNS label name.
func deriveWatchName(opts watchOptions) (string, error) {
	name := opts.Name
	if name == "" {
		if opts.AppName == "" {
			return "", errors.New("--name is required when targeting with --label (there is no app name to derive the PodTrace name from)")
		}
		name = opts.AppName
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if errs := k8svalidation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return "", fmt.Errorf("invalid PodTrace name %q: %s (override with --name)", name, strings.Join(errs, "; "))
	}
	if len(name) > 63 {
		return "", fmt.Errorf("PodTrace name %q exceeds 63 characters; pass a shorter --name", name)
	}
	return name, nil
}

// marshalPodTraceYAML renders a PodTrace in the same shape `kubectl get -o yaml`
// would emit (mirrors marshalSessionYAML in schedule_yaml.go).
func marshalPodTraceYAML(pt *podtracev1alpha1.PodTrace) ([]byte, error) {
	pt.APIVersion = podtracev1alpha1.GroupVersion.String()
	pt.Kind = "PodTrace"
	return sigsyaml.Marshal(pt)
}
