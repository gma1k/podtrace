package operator

import (
	"context"
	"fmt"
	"os"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

const DefaultTracerConfigName = "default"

const BootstrapImageEnv = "PODTRACE_BOOTSTRAP_IMAGE"

type BootstrapDefaultTracerConfig struct {
	Client          client.Client
	SystemNamespace string
	FallbackImage   string
}

func (b *BootstrapDefaultTracerConfig) NeedLeaderElection() bool { return true }

func (b *BootstrapDefaultTracerConfig) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("tracerconfig-bootstrap")

	var existing podtracev1alpha1.TracerConfigList
	if err := b.Client.List(ctx, &existing); err != nil {
		logger.Error(err, "list TracerConfig failed; skipping bootstrap")
		return nil
	}
	if len(existing.Items) > 0 {
		logger.Info("TracerConfig already present; bootstrap is a no-op",
			"count", len(existing.Items),
			"first", existing.Items[0].Name)
		return nil
	}

	image := os.Getenv(BootstrapImageEnv)
	if image == "" {
		image = b.FallbackImage
	}
	if image == "" {
		logger.Info("no image configured; bootstrap skipped",
			"hint", fmt.Sprintf("set %s on the operator Deployment", BootstrapImageEnv))
		return nil
	}

	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: DefaultTracerConfigName,
			Annotations: map[string]string{
				"podtrace.io/bootstrap-source": "operator",
			},
		},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: image,
		},
	}

	if err := b.Client.Create(ctx, tc); err != nil {
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
