package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func managedBy(manager, fields string) metav1.ManagedFieldsEntry {
	return metav1.ManagedFieldsEntry{
		Manager:   manager,
		Operation: metav1.ManagedFieldsOperationUpdate,
		FieldsV1:  metav1.NewFieldsV1(fields),
	}
}

const oldOperatorFields = `{"f:metadata":{"f:annotations":{"f:podtrace.io/bootstrap-source":{}}},` +
	`"f:spec":{"f:image":{},"f:agent":{"f:resources":{}},"f:session":{"f:resources":{}}}}`

func legacyBootstrapped(image string) *podtracev1alpha1.TracerConfig {
	tc := NewBootstrapTracerConfig("default", image, "podtrace-system")
	delete(tc.Annotations, bootstrapFieldsAnnotation)
	tc.Spec.Tolerations = nil
	tc.Spec.Agent.Metrics = nil
	tc.ManagedFields = []metav1.ManagedFieldsEntry{managedBy(bootstrapFieldManager, oldOperatorFields)}
	return tc
}

func desiredBootstrap() *podtracev1alpha1.TracerConfig {
	return NewBootstrapTracerConfig("default", "ghcr.io/gma1k/podtrace:new", "podtrace-system")
}

func TestAnOldBootstrapObjectIsBroughtUpToDate(t *testing.T) {
	got, changed := adoptBootstrapDefaults(legacyBootstrapped("ghcr.io/gma1k/podtrace:old"), desiredBootstrap())

	if !changed {
		t.Fatal("nothing changed on an object an older operator created")
	}
	if got.Spec.Image != "ghcr.io/gma1k/podtrace:new" {
		t.Errorf("image = %s; after an OLM upgrade the agents would keep running the old version", got.Spec.Image)
	}
	if len(got.Spec.Tolerations) == 0 {
		t.Error("no tolerations added; tainted nodes, the control plane first, would stay without an agent")
	}
	if ns := excludeNamespacesOf(got); len(ns) != 1 || ns[0] != "podtrace-system" {
		t.Errorf("excludeNamespaces = %v, want podtrace-system", ns)
	}
	if got.Annotations[bootstrapFieldsAnnotation] == "" {
		t.Error("the written fields were not recorded, so a later removal could not be told from never-set")
	}
}

func TestAFieldTheUserChangedIsLeftAlone(t *testing.T) {
	existing := legacyBootstrapped("registry.example.com/podtrace:pinned")
	existing.ManagedFields = append(existing.ManagedFields,
		managedBy("kubectl-edit", `{"f:spec":{"f:image":{}}}`))
	existing.ManagedFields[0] = managedBy(bootstrapFieldManager,
		`{"f:spec":{"f:agent":{"f:resources":{}},"f:session":{"f:resources":{}}}}`)

	got, _ := adoptBootstrapDefaults(existing, desiredBootstrap())
	if got.Spec.Image != "registry.example.com/podtrace:pinned" {
		t.Errorf("image = %s; a pinned image was overwritten by the operator", got.Spec.Image)
	}
}

func TestAFieldTheUserRemovedStaysRemoved(t *testing.T) {
	existing := desiredBootstrap()
	existing.Spec.Tolerations = nil
	existing.ManagedFields = []metav1.ManagedFieldsEntry{managedBy(bootstrapFieldManager, `{"f:spec":{"f:image":{}}}`)}

	got, _ := adoptBootstrapDefaults(existing, desiredBootstrap())
	if got.Spec.Tolerations != nil {
		t.Errorf("tolerations = %v; the user removed them and the operator put them back", got.Spec.Tolerations)
	}
}

func TestACurrentObjectIsNotPatched(t *testing.T) {
	first, _ := adoptBootstrapDefaults(legacyBootstrapped("ghcr.io/gma1k/podtrace:old"), desiredBootstrap())
	first.ManagedFields = []metav1.ManagedFieldsEntry{managedBy(bootstrapFieldManager,
		`{"f:spec":{"f:image":{},"f:tolerations":{},"f:agent":{"f:resources":{},"f:metrics":{"f:excludeNamespaces":{}}},"f:session":{"f:resources":{}}}}`)}

	if _, changed := adoptBootstrapDefaults(first, desiredBootstrap()); changed {
		t.Error("a second pass changed an object that is already current; every operator restart would patch it")
	}
}

func TestEquivalentQuantitiesAreNotAChange(t *testing.T) {
	existing := desiredBootstrap()
	existing.Spec.Agent.Resources.Limits[corev1.ResourceCPU] = resource.MustParse("1000m")
	existing.ManagedFields = []metav1.ManagedFieldsEntry{managedBy(bootstrapFieldManager,
		`{"f:spec":{"f:image":{},"f:tolerations":{},"f:agent":{"f:resources":{},"f:metrics":{"f:excludeNamespaces":{}}},"f:session":{"f:resources":{}}}}`)}

	if _, changed := adoptBootstrapDefaults(existing, desiredBootstrap()); changed {
		t.Error("1000m and 1 CPU were treated as different, which patches the object for nothing")
	}
}

func TestStatusWritesDoNotCountAsOwnership(t *testing.T) {
	entries := []metav1.ManagedFieldsEntry{{
		Manager:     "someone-else",
		Subresource: "status",
		FieldsV1:    metav1.NewFieldsV1(`{"f:spec":{"f:image":{}}}`),
	}, managedBy(bootstrapFieldManager, `{"f:spec":{"f:image":{}}}`)}

	if !ownedOnlyBy(entries, []string{"spec", "image"}, bootstrapFieldManager) {
		t.Error("a status-subresource entry took ownership of a spec field")
	}
	if ownedOnlyBy(nil, []string{"spec", "image"}, bootstrapFieldManager) {
		t.Error("a field with no recorded owner was reported as owned")
	}
	if fieldsContain([]byte("not json"), []string{"spec"}) {
		t.Error("malformed managedFields were read as containing the field")
	}
}

func TestAFreshBootstrapIsNotPatchedOnTheNextStart(t *testing.T) {
	tc := desiredBootstrap()
	tc.ManagedFields = []metav1.ManagedFieldsEntry{managedBy(bootstrapFieldManager,
		`{"f:spec":{"f:image":{},"f:tolerations":{},"f:agent":{"f:resources":{},"f:metrics":{"f:excludeNamespaces":{}}},"f:session":{"f:resources":{}}}}`)}
	if _, changed := adoptBootstrapDefaults(tc, desiredBootstrap()); changed {
		t.Error("an object the current operator just created was patched on the next start")
	}
}

func TestAFreshBootstrapRecordsWhatItSet(t *testing.T) {
	tc := NewBootstrapTracerConfig("default", "img", "podtrace-system")
	want := "agent.metrics.excludeNamespaces,agent.resources,image,session.resources,tolerations"
	if got := tc.Annotations[bootstrapFieldsAnnotation]; got != want {
		t.Errorf("%s = %q, want %q", bootstrapFieldsAnnotation, got, want)
	}
}
