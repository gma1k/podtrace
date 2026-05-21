package operator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/pkg/exporter/bundle"
)

// marshalBundleToYAML converts the flat ConfigMap representation the
// existing renderBundlePayload emits into the structured YAML the CLI's
// --exporter-from-file reads. Splitting this out keeps the operator's
// bundle reconciler free of YAML concerns and lets the shared bundle
// package own the wire format.
func marshalBundleToYAML(data map[string]string) (string, error) {
	p, err := bundle.FromConfigMapData(data)
	if err != nil {
		return "", err
	}
	raw, err := bundle.ToYAML(p)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// SessionBundleName returns the ConfigMap/Secret name for a session's
// exporter bundle. Keyed by session UID (not name) so two sessions with
// the same name across namespaces do not collide on a single bundle
// object. The agent does not read session bundles — they live in the
// system namespace solely so the per-node session Job can mount them.
func SessionBundleName(sessionUID types.UID) string {
	return "pts-bundle-" + shortUID(sessionUID)
}

// ensureSessionExporterBundle creates-or-updates the ConfigMap + optional
// companion Secret the session Job mounts at /etc/podtrace/exporter/.
// Reuses renderBundlePayload so the session Job consumes bytes-identical
// exporter configuration to what a continuous PodTrace's agent sees.
func ensureSessionExporterBundle(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, ec *podtracev1alpha1.ExporterConfig, systemNS string) error {
	name := SessionBundleName(s.UID)

	payload, credSecretRef, err := renderBundlePayload(policyFromSession(s), ec, nil)
	if err != nil {
		return fmt.Errorf("render session bundle payload: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, cm, func() error {
		cm.Labels = mergeLabels(cm.Labels, map[string]string{
			LabelManagedBy:      ManagedByValue,
			LabelComponent:      ComponentBundle,
			LabelSessionName:    s.Name,
			LabelSessionNS:      s.Namespace,
			LabelExporterConfig: ec.Name,
		})
		cm.Annotations = mergeLabels(cm.Annotations, map[string]string{
			BundleAnnotationSourceRef: ec.Namespace + "/" + ec.Name,
		})
		bundleYAML, err := marshalBundleToYAML(payload)
		if err != nil {
			return err
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data["bundle.yaml"] = bundleYAML
		for k, v := range payload {
			cm.Data[k] = v
		}
		return nil
	}); err != nil {
		return fmt.Errorf("session bundle ConfigMap: %w", err)
	}

	if credSecretRef != nil {
		credData, err := loadCredentialSecret(ctx, c, ec.Namespace, *credSecretRef)
		if err != nil {
			return fmt.Errorf("load session credential Secret: %w", err)
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS},
		}
		if _, err := controllerutil.CreateOrUpdate(ctx, c, secret, func() error {
			secret.Labels = mergeLabels(secret.Labels, map[string]string{
				LabelManagedBy:      ManagedByValue,
				LabelComponent:      ComponentBundle,
				LabelSessionName:    s.Name,
				LabelSessionNS:      s.Namespace,
				LabelExporterConfig: ec.Name,
			})
			secret.Annotations = mergeLabels(secret.Annotations, map[string]string{
				BundleAnnotationSourceRef: ec.Namespace + "/" + ec.Name,
			})
			secret.Type = corev1.SecretTypeOpaque
			secret.Data = credData
			return nil
		}); err != nil {
			return fmt.Errorf("session bundle Secret: %w", err)
		}
	}
	return nil
}

// loadCredentialSecret fetches exactly the one SecretKeySelector an
// ExporterConfig references and returns the value under the fixed
// "credential" key.
func loadCredentialSecret(ctx context.Context, c client.Client, namespace string, ref podtracev1alpha1.SecretKeySelector) (map[string][]byte, error) {
	var src corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &src); err != nil {
		return nil, fmt.Errorf("get Secret %s/%s: %w", namespace, ref.Name, err)
	}
	val, ok := src.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	return map[string][]byte{"credential": val}, nil
}
