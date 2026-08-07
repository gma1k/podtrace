package v1alpha1

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/fleet"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-tracerconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=tracerconfigs,verbs=create;update,versions=v1alpha1,name=vtracerconfig.podtrace.io,admissionReviewVersions=v1

// TracerConfigCustomValidator guards the invariants of a multi-fleet
// cluster. Each TracerConfig owns its own agent DaemonSet, and fleets are
// supposed to select disjoint node sets.
type TracerConfigCustomValidator struct {
	Client client.Client
}

func SetupTracerConfigWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &podtracev1alpha1.TracerConfig{}).
		WithValidator(&TracerConfigCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

var _ admission.Validator[*podtracev1alpha1.TracerConfig] = &TracerConfigCustomValidator{}

func (v *TracerConfigCustomValidator) ValidateCreate(ctx context.Context, tc *podtracev1alpha1.TracerConfig) (admission.Warnings, error) {
	return v.validate(ctx, tc)
}

func (v *TracerConfigCustomValidator) ValidateUpdate(ctx context.Context, oldTC, newTC *podtracev1alpha1.TracerConfig) (admission.Warnings, error) {
	if oldTC != nil && specUnchanged(oldTC.Spec, newTC.Spec) {
		return nil, nil
	}
	return v.validate(ctx, newTC)
}

func (v *TracerConfigCustomValidator) ValidateDelete(_ context.Context, _ *podtracev1alpha1.TracerConfig) (admission.Warnings, error) {
	return nil, nil
}

func (v *TracerConfigCustomValidator) validate(ctx context.Context, tc *podtracev1alpha1.TracerConfig) (admission.Warnings, error) {
	if err := validateTracerConfigNameLength(tc.Name); err != nil {
		return nil, err
	}
	if v.Client == nil {
		return nil, nil
	}

	var others podtracev1alpha1.TracerConfigList
	if err := v.Client.List(ctx, &others); err != nil {
		return nil, fmt.Errorf("list TracerConfigs to check for fleet overlap: %w", err)
	}
	siblings := make([]podtracev1alpha1.TracerConfig, 0, len(others.Items))
	for i := range others.Items {
		if others.Items[i].Name != tc.Name {
			siblings = append(siblings, others.Items[i])
		}
	}

	if err := validateSelectorCollision(tc, siblings); err != nil {
		return nil, err
	}
	return v.warnOnCurrentOverlap(ctx, tc, siblings), nil
}

func validateTracerConfigNameLength(name string) error {
	if len(name) > podtracev1alpha1.MaxTracerConfigNameLength {
		return fmt.Errorf(
			"metadata.name is %d characters, limit is %d: the name becomes the value of the podtrace.io/tracer-config label on the agent DaemonSet's immutable pod selector, and Kubernetes caps label values at %d characters",
			len(name), podtracev1alpha1.MaxTracerConfigNameLength, podtracev1alpha1.MaxTracerConfigNameLength)
	}
	return nil
}

// validateSelectorCollision rejects the two overlaps that hold for every
// possible set of node labels.
func validateSelectorCollision(tc *podtracev1alpha1.TracerConfig, siblings []podtracev1alpha1.TracerConfig) error {
	for i := range siblings {
		other := &siblings[i]

		if isClusterWide(&tc.Spec) && isClusterWide(&other.Spec) {
			return fmt.Errorf(
				"spec.nodeSelector: TracerConfig %q already targets every node, and this config would too; two cluster-wide fleets attach two agents to every node and count every event twice. Give one of them a nodeSelector or a required nodeAffinity",
				other.Name)
		}

		if len(tc.Spec.NodeSelector) > 0 &&
			equality.Semantic.DeepEqual(tc.Spec.NodeSelector, other.Spec.NodeSelector) {
			return fmt.Errorf(
				"spec.nodeSelector: identical to TracerConfig %q, so the two fleets target exactly the same nodes and every event on them is counted twice. Node pools must be disjoint",
				other.Name)
		}
	}
	return nil
}

// isClusterWide delegates to the partition package so admission and the
// reconciler cannot drift on what "targets every node" means — the same
// predicate also decides fleet precedence in fleet.Outranks.
func isClusterWide(spec *podtracev1alpha1.TracerConfigSpec) bool {
	return fleet.IsClusterWide(spec)
}

// warnOnCurrentOverlap reports fleets that share nodes as the cluster is
// labelled right now.
func (v *TracerConfigCustomValidator) warnOnCurrentOverlap(
	ctx context.Context,
	tc *podtracev1alpha1.TracerConfig,
	siblings []podtracev1alpha1.TracerConfig,
) admission.Warnings {
	if len(siblings) == 0 {
		return nil
	}
	var nodes corev1.NodeList
	if err := v.Client.List(ctx, &nodes); err != nil {
		return nil
	}

	rivals := map[string]int{}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !fleet.NodeTargetedBy(node, tc) {
			continue
		}
		for j := range siblings {
			if fleet.NodeTargetedBy(node, &siblings[j]) {
				rivals[siblings[j].Name]++
			}
		}
	}
	if len(rivals) == 0 {
		return nil
	}

	names := make([]string, 0, len(rivals))
	for name := range rivals {
		names = append(names, name)
	}
	sort.Strings(names)

	warnings := make(admission.Warnings, 0, len(names))
	for _, name := range names {
		warnings = append(warnings, fmt.Sprintf(
			"shares %d node(s) with TracerConfig %q as the cluster is labelled now; both agent DaemonSets will run there and every event on those nodes will be counted twice. Check the Conflict condition after applying",
			rivals[name], name))
	}
	return warnings
}
