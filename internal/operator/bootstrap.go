package operator

import (
	"context"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

const DefaultTracerConfigName = "default"

const BootstrapImageEnv = "PODTRACE_BOOTSTRAP_IMAGE"

type BootstrapDefaultTracerConfig struct {
	Client           client.Client
	SystemNamespace  string
	FallbackImage    string
	TracerConfigName string
}

func (b *BootstrapDefaultTracerConfig) NeedLeaderElection() bool { return true }

func (b *BootstrapDefaultTracerConfig) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("tracerconfig-bootstrap")

	var existing podtracev1alpha1.TracerConfigList
	var listErr error
	for attempt := 0; attempt < 5; attempt++ {
		if listErr = b.Client.List(ctx, &existing); listErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	if listErr != nil {
		logger.Error(listErr, "list TracerConfig failed after retries; skipping bootstrap")
		return nil
	}
	image := os.Getenv(BootstrapImageEnv)
	if image == "" {
		image = b.FallbackImage
	}
	name := b.TracerConfigName
	if name == "" {
		name = DefaultTracerConfigName
	}

	if len(existing.Items) > 0 {
		for i := range existing.Items {
			if tc := &existing.Items[i]; tc.Name == name && tc.Annotations[bootstrapSourceAnnotation] == "operator" && image != "" {
				return b.keepCurrent(ctx, tc, NewBootstrapTracerConfig(name, image, b.SystemNamespace))
			}
		}
		logger.Info("TracerConfig already present; bootstrap is a no-op",
			"count", len(existing.Items),
			"first", existing.Items[0].Name)
		return nil
	}

	if image == "" {
		logger.Info("no image configured; bootstrap skipped",
			"hint", fmt.Sprintf("set %s on the operator Deployment", BootstrapImageEnv))
		return nil
	}

	tc := NewBootstrapTracerConfig(name, image, b.SystemNamespace)

	if err := b.Client.Create(ctx, tc, client.FieldOwner(bootstrapFieldManager)); err != nil {
		if apierrors.IsAlreadyExists(err) {
			logger.Info("TracerConfig created concurrently; deferring")
			return nil
		}
		return fmt.Errorf("create default TracerConfig: %w", err)
	}
	logger.Info("created default TracerConfig",
		"name", tc.Name, "image", image, "source", "operator-bootstrap")
	return nil
}

// NewBootstrapTracerConfig is the TracerConfig the operator creates when the
// cluster has none, which is what OLM and raw-manifest installs run on.
func NewBootstrapTracerConfig(name, image, systemNamespace string) *podtracev1alpha1.TracerConfig {
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				bootstrapSourceAnnotation: "operator",
			},
		},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:       image,
			Tolerations: defaultAgentTolerations(),
			Agent: podtracev1alpha1.AgentSpec{
				Resources: defaultAgentResources(),
			},
			Session: podtracev1alpha1.SessionRuntimeSpec{
				Resources: defaultSessionResources(),
			},
		},
	}
	if systemNamespace != "" {
		tc.Spec.Agent.Metrics = &podtracev1alpha1.AgentMetricsSpec{
			ExcludeNamespaces: []string{systemNamespace},
		}
	}
	tc.Annotations[bootstrapFieldsAnnotation] = bootstrapFieldNames(tc)
	return tc
}

// keepCurrent brings an operator-created TracerConfig up to this operator's
// defaults, field by field, leaving alone anything a user has changed.
func (b *BootstrapDefaultTracerConfig) keepCurrent(ctx context.Context, existing, desired *podtracev1alpha1.TracerConfig) error {
	logger := log.FromContext(ctx).WithName("tracerconfig-bootstrap")
	updated, changed := adoptBootstrapDefaults(existing, desired)
	if !changed {
		logger.Info("bootstrapped TracerConfig is current", "name", existing.Name)
		return nil
	}
	if err := b.Client.Patch(ctx, updated, client.MergeFromWithOptions(existing, client.MergeFromWithOptimisticLock{}), client.FieldOwner(bootstrapFieldManager)); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			logger.Info("bootstrapped TracerConfig changed while being updated; leaving it", "name", existing.Name)
			return nil
		}
		return fmt.Errorf("update bootstrapped TracerConfig: %w", err)
	}
	logger.Info("brought bootstrapped TracerConfig up to this operator's defaults",
		"name", existing.Name, "image", updated.Spec.Image,
		"fields", updated.Annotations[bootstrapFieldsAnnotation])
	return nil
}

// defaultAgentTolerations mirrors the chart's values.yaml agent tolerations.
// Without them an OLM install runs no agent on a tainted node, most often the
// control plane, and every pod there goes unobserved.
func defaultAgentTolerations() []corev1.Toleration {
	return []corev1.Toleration{{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
}

// defaultAgentResources mirrors the chart's values.yaml agent resource
// defaults so a non-Helm (OLM / raw-kubectl) or race-bootstrapped TracerConfig
// still bounds the agent DaemonSet.
func defaultAgentResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1000m"),
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
	}
}

// defaultSessionResources mirrors the chart's values.yaml session resource
// defaults for the per-session Job pods.
func defaultSessionResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1000m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}
