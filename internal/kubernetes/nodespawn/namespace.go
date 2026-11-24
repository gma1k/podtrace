package nodespawn

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultSpawnNamespace is where spawn pods and their credential Secrets
// live unless the user names another namespace.
const DefaultSpawnNamespace = "podtrace-cli"

const podSecurityEnforceLabel = "pod-security.kubernetes.io/enforce"

// tenancyMarkers are labels and annotations that self-service namespace
// controllers put on a namespace a tenant created or owns.
var (
	tenancyLabels      = []string{"capsule.clastix.io/tenant"}
	tenancyAnnotations = []string{"hnc.x-k8s.io/subnamespace-of", "field.cattle.io/projectId"}
)

// EnsureSpawnNamespace makes sure the default spawn namespace exists,
// creating it with the privileged PodSecurity level the spawn pod needs.
func EnsureSpawnNamespace(ctx context.Context, clientset kubernetes.Interface, namespace string) error {
	existing, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	switch {
	case err == nil:
		return verifySpawnNamespace(existing)
	case apierrors.IsForbidden(err):
		return fmt.Errorf("nodespawn: may not read spawn namespace %q, so it cannot be checked "+
			"for an owner other than podtrace; pass --spawn-namespace=%s (or set "+
			"PODTRACE_SPAWN_NAMESPACE) if a cluster admin created it for podtrace: %w",
			namespace, namespace, err)
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
	case err == nil:
		return nil
	case apierrors.IsAlreadyExists(err):
		raced, getErr := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("nodespawn: spawn namespace %q was created concurrently and cannot be read: %w", namespace, getErr)
		}
		return verifySpawnNamespace(raced)
	case apierrors.IsForbidden(err):
		return fmt.Errorf("nodespawn: spawn namespace %q does not exist and you may not create it. "+
			"Ask a cluster admin to run:\n"+
			"  kubectl create namespace %s && kubectl label ns/%s %s=privileged %s=%s\n"+
			"or pass --spawn-namespace=<ns> to use a namespace that allows privileged pods "+
			"(avoid a tenant namespace: anyone with pods/exec there gets a node-privileged shell). "+
			"Underlying error: %w", namespace, namespace, namespace, podSecurityEnforceLabel,
			LabelManagedBy, ManagedByValue, err)
	default:
		return fmt.Errorf("nodespawn: create spawn namespace %q: %w", namespace, err)
	}
}

// verifySpawnNamespace accepts an existing default spawn namespace only when
// it is marked as podtrace's and nothing marks it as a tenant's.
func verifySpawnNamespace(ns *corev1.Namespace) error {
	if owner := tenantOwnership(ns); owner != "" {
		return fmt.Errorf("nodespawn: spawn namespace %q belongs to a tenant (%s); the spawn pod is "+
			"node-privileged, so it will not run there. Delete or rename that namespace, or pass "+
			"--spawn-namespace=<ns> to choose a namespace only cluster admins control",
			ns.Name, owner)
	}
	if ns.Labels[LabelManagedBy] != ManagedByValue {
		return fmt.Errorf("nodespawn: spawn namespace %q exists but podtrace did not create it "+
			"(no %s=%s label). Anyone who created it can exec into the node-privileged spawn pod "+
			"and read its credentials. If a cluster admin made it for podtrace, run:\n"+
			"  kubectl label ns/%s %s=%s\n"+
			"or pass --spawn-namespace=%s to use it as it is",
			ns.Name, LabelManagedBy, ManagedByValue, ns.Name, LabelManagedBy, ManagedByValue, ns.Name)
	}
	return nil
}

func tenantOwnership(ns *corev1.Namespace) string {
	var marks []string
	for _, ref := range ns.OwnerReferences {
		marks = append(marks, "owned by "+ref.Kind+"/"+ref.Name)
	}
	for _, key := range tenancyLabels {
		if v, ok := ns.Labels[key]; ok {
			marks = append(marks, "label "+key+"="+v)
		}
	}
	for _, key := range tenancyAnnotations {
		if v, ok := ns.Annotations[key]; ok {
			marks = append(marks, "annotation "+key+"="+v)
		}
	}
	return strings.Join(marks, ", ")
}
