package nodespawn

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultSpawnNamespace is where spawn pods and their credential Secrets
// live unless the user names another namespace.
const DefaultSpawnNamespace = "podtrace-cli"

const podSecurityEnforceLabel = "pod-security.kubernetes.io/enforce"

// EnsureSpawnNamespace makes sure the default spawn namespace exists,
// creating it with the privileged PodSecurity level the spawn pod needs.
func EnsureSpawnNamespace(ctx context.Context, clientset kubernetes.Interface, namespace string) error {
	_, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	switch {
	case err == nil, apierrors.IsForbidden(err):
		return nil
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("nodespawn: get spawn namespace %q: %w", namespace, err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespace,
		Labels: map[string]string{
			LabelManagedBy:          ManagedByValue,
			podSecurityEnforceLabel: "privileged",
		},
	}}
	_, err = clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	switch {
	case err == nil, apierrors.IsAlreadyExists(err):
		return nil
	case apierrors.IsForbidden(err):
		return fmt.Errorf("nodespawn: spawn namespace %q does not exist and you may not create it. "+
			"Ask a cluster admin to run:\n"+
			"  kubectl create namespace %s && kubectl label ns/%s %s=privileged\n"+
			"or pass --spawn-namespace=<ns> to use a namespace that allows privileged pods "+
			"(avoid a tenant namespace: anyone with pods/exec there gets a node-privileged shell). "+
			"Underlying error: %w", namespace, namespace, namespace, podSecurityEnforceLabel, err)
	default:
		return fmt.Errorf("nodespawn: create spawn namespace %q: %w", namespace, err)
	}
}
