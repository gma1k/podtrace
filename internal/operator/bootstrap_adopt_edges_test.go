package operator

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const allOperatorFields = `{"f:spec":{"f:image":{},"f:tolerations":{},"f:agent":{"f:resources":{},` +
	`"f:metrics":{"f:excludeNamespaces":{}}},"f:session":{"f:resources":{}}}}`

func TestNewResourceDefaultsReachResourcesTheOperatorStillOwns(t *testing.T) {
	existing := desiredBootstrap()
	existing.Spec.Agent.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("512Mi")
	existing.Spec.Session.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("128Mi")
	existing.ManagedFields = []metav1.ManagedFieldsEntry{managedBy(bootstrapFieldManager, allOperatorFields)}

	got, changed := adoptBootstrapDefaults(existing, desiredBootstrap())
	want := desiredBootstrap()
	if !changed {
		t.Fatal("new resource defaults were not applied to resources the operator still owns")
	}
	if m := got.Spec.Agent.Resources.Limits[corev1.ResourceMemory]; m.Cmp(want.Spec.Agent.Resources.Limits[corev1.ResourceMemory]) != 0 {
		t.Errorf("agent memory limit = %s, want the current default", m.String())
	}
	if m := got.Spec.Session.Resources.Limits[corev1.ResourceMemory]; m.Cmp(want.Spec.Session.Resources.Limits[corev1.ResourceMemory]) != 0 {
		t.Errorf("session memory limit = %s, want the current default", m.String())
	}
}

func TestAFieldTheDesiredObjectLeavesOutIsNotTouched(t *testing.T) {
	existing := desiredBootstrap()
	existing.Spec.Agent.Metrics.ExcludeNamespaces = []string{"elsewhere"}
	existing.ManagedFields = []metav1.ManagedFieldsEntry{managedBy(bootstrapFieldManager, allOperatorFields)}

	got, _ := adoptBootstrapDefaults(existing, NewBootstrapTracerConfig("default", "ghcr.io/gma1k/podtrace:new", ""))
	if ns := excludeNamespacesOf(got); len(ns) != 1 || ns[0] != "elsewhere" {
		t.Errorf("excludeNamespaces = %v; an operator with no system namespace has nothing to "+
			"say about it and must leave it", ns)
	}
}

func TestAnObjectWithNoAnnotationsGetsTheRecord(t *testing.T) {
	existing := legacyBootstrapped("ghcr.io/gma1k/podtrace:old")
	existing.Annotations = nil

	got, changed := adoptBootstrapDefaults(existing, desiredBootstrap())
	if !changed || got.Annotations[bootstrapFieldsAnnotation] == "" {
		t.Errorf("annotations = %v; the written fields must be recorded even when the object "+
			"had no annotations", got.Annotations)
	}
}

func bootstrappedClient(t *testing.T, patchErr error) client.Client {
	t.Helper()
	scheme, err := NewScheme()
	if err != nil {
		t.Fatalf("scheme: %v", err)
	}
	existing := legacyBootstrapped("ghcr.io/gma1k/podtrace:old")
	existing.ManagedFields = nil
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				return patchErr
			},
		}).Build()
}

func startBootstrapOn(c client.Client) error {
	b := &BootstrapDefaultTracerConfig{Client: c, SystemNamespace: "podtrace-system", FallbackImage: "ghcr.io/gma1k/podtrace:new"}
	return b.Start(context.Background())
}

func TestAnObjectThatChangedDuringTheUpdateIsLeftAlone(t *testing.T) {
	gr := schema.GroupResource{Group: "podtrace.io", Resource: "tracerconfigs"}
	for name, err := range map[string]error{
		"conflict":  apierrors.NewConflict(gr, "default", errors.New("modified")),
		"not found": apierrors.NewNotFound(gr, "default"),
	} {
		t.Run(name, func(t *testing.T) {
			if got := startBootstrapOn(bootstrappedClient(t, err)); got != nil {
				t.Errorf("Start = %v; a user edit or delete racing the update is theirs to "+
					"win, and must not fail the operator's start", got)
			}
		})
	}
}

func TestAFailedUpdateIsReported(t *testing.T) {
	if err := startBootstrapOn(bootstrappedClient(t, errors.New("apiserver unavailable"))); err == nil {
		t.Error("an update the API server rejected was reported as success")
	}
}
