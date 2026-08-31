package storagemigrate

import (
	"context"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

type fakeCRDClient struct {
	crd     *apiextensionsv1.CustomResourceDefinition
	updates int
}

func (f *fakeCRDClient) Get(context.Context, string, metav1.GetOptions) (*apiextensionsv1.CustomResourceDefinition, error) {
	return f.crd.DeepCopy(), nil
}

func (f *fakeCRDClient) UpdateStatus(_ context.Context, crd *apiextensionsv1.CustomResourceDefinition, _ metav1.UpdateOptions) (*apiextensionsv1.CustomResourceDefinition, error) {
	f.updates++
	f.crd = crd.DeepCopy()
	return f.crd, nil
}

func testCRD(storageVersion string, served []string, stored []string) *apiextensionsv1.CustomResourceDefinition {
	versions := make([]apiextensionsv1.CustomResourceDefinitionVersion, 0, len(served))
	for _, v := range served {
		versions = append(versions, apiextensionsv1.CustomResourceDefinitionVersion{
			Name:    v,
			Served:  true,
			Storage: v == storageVersion,
		})
	}
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "widgets.podtrace.io"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group:    "podtrace.io",
			Scope:    apiextensionsv1.NamespaceScoped,
			Names:    apiextensionsv1.CustomResourceDefinitionNames{Plural: "widgets", Kind: "Widget"},
			Versions: versions,
		},
		Status: apiextensionsv1.CustomResourceDefinitionStatus{StoredVersions: stored},
	}
}

func widget(namespace, name, version string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "podtrace.io/" + version,
		"kind":       "Widget",
		"metadata":   map[string]any{"namespace": namespace, "name": name},
		"spec":       map[string]any{"samplePercent": int64(20)},
	}}
}

func fakeDynamic(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "podtrace.io", Version: "v1beta1", Resource: "widgets"}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{gvr: "WidgetList"}, objs...)
}

func TestStorageVersionOfFindsTheStorageVersion(t *testing.T) {
	got, err := StorageVersionOf(testCRD("v1beta1", []string{"v1alpha1", "v1beta1"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1beta1" {
		t.Fatalf("got %q, want v1beta1", got)
	}
}

func TestStorageVersionOfErrorsWhenNoneIsMarked(t *testing.T) {
	crd := testCRD("", []string{"v1alpha1"}, nil)
	if _, err := StorageVersionOf(crd); err == nil {
		t.Fatal("expected an error when no version is storage: true")
	}
}

func TestStaleStoredVersionsIgnoresTheStorageVersion(t *testing.T) {
	got := StaleStoredVersions([]string{"v1alpha1", "v1beta1"}, "v1beta1")
	if len(got) != 1 || got[0] != "v1alpha1" {
		t.Fatalf("got %v, want [v1alpha1]", got)
	}
}

func TestStaleStoredVersionsReturnsNilWhenAlreadyClean(t *testing.T) {
	if got := StaleStoredVersions([]string{"v1beta1"}, "v1beta1"); got != nil {
		t.Fatalf("got %v, want nil so the caller skips the status write", got)
	}
}

func TestMigrateRewritesEveryObjectAndUnpinsTheOldVersion(t *testing.T) {
	crds := &fakeCRDClient{crd: testCRD("v1beta1", []string{"v1alpha1", "v1beta1"}, []string{"v1alpha1", "v1beta1"})}
	dyn := fakeDynamic(widget("a", "one", "v1beta1"), widget("b", "two", "v1beta1"))

	res, err := Migrate(context.Background(), crds, dyn, "widgets.podtrace.io", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Objects != 2 || res.Rewritten != 2 {
		t.Fatalf("objects=%d rewritten=%d, want 2/2", res.Objects, res.Rewritten)
	}
	if len(res.Unpinned) != 1 || res.Unpinned[0] != "v1alpha1" {
		t.Fatalf("unpinned = %v, want [v1alpha1]", res.Unpinned)
	}
	if got := crds.crd.Status.StoredVersions; len(got) != 1 || got[0] != "v1beta1" {
		t.Fatalf("storedVersions = %v, want [v1beta1]", got)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	crds := &fakeCRDClient{crd: testCRD("v1beta1", []string{"v1beta1"}, []string{"v1beta1"})}
	dyn := fakeDynamic(widget("a", "one", "v1beta1"))

	first, err := Migrate(context.Background(), crds, dyn, "widgets.podtrace.io", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Migrate(context.Background(), crds, dyn, "widgets.podtrace.io", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Unpinned) != 0 || len(second.Unpinned) != 0 {
		t.Fatalf("nothing to unpin, got %v then %v", first.Unpinned, second.Unpinned)
	}
	if crds.updates != 0 {
		t.Fatalf("storedVersions was written %d time(s) with nothing stale", crds.updates)
	}
}

func TestMigrateDryRunWritesNothing(t *testing.T) {
	crds := &fakeCRDClient{crd: testCRD("v1beta1", []string{"v1alpha1", "v1beta1"}, []string{"v1alpha1", "v1beta1"})}
	dyn := fakeDynamic(widget("a", "one", "v1beta1"))

	res, err := Migrate(context.Background(), crds, dyn, "widgets.podtrace.io", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Objects != 1 {
		t.Fatalf("objects = %d, want 1", res.Objects)
	}
	if res.Rewritten != 0 {
		t.Fatalf("dry run rewrote %d object(s)", res.Rewritten)
	}
	if crds.updates != 0 {
		t.Fatal("dry run wrote storedVersions")
	}
	if len(res.Unpinned) != 1 {
		t.Fatalf("dry run should still report what it would unpin, got %v", res.Unpinned)
	}
	if got := crds.crd.Status.StoredVersions; len(got) != 2 {
		t.Fatalf("storedVersions changed during a dry run: %v", got)
	}
}

func TestMigrateOnEmptyCRDStillUnpins(t *testing.T) {
	crds := &fakeCRDClient{crd: testCRD("v1beta1", []string{"v1alpha1", "v1beta1"}, []string{"v1alpha1", "v1beta1"})}
	dyn := fakeDynamic()

	res, err := Migrate(context.Background(), crds, dyn, "widgets.podtrace.io", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Objects != 0 {
		t.Fatalf("objects = %d, want 0", res.Objects)
	}
	if got := crds.crd.Status.StoredVersions; len(got) != 1 || got[0] != "v1beta1" {
		t.Fatalf("storedVersions = %v, want [v1beta1] — no data means nothing pins the old version", got)
	}
}

func TestMigrateReportsClusterScopedObjects(t *testing.T) {
	crd := testCRD("v1beta1", []string{"v1beta1"}, []string{"v1beta1"})
	crd.Spec.Scope = apiextensionsv1.ClusterScoped
	crds := &fakeCRDClient{crd: crd}
	dyn := fakeDynamic(widget("", "cluster-wide", "v1beta1"))

	res, err := Migrate(context.Background(), crds, dyn, "widgets.podtrace.io", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Objects != 1 || res.Rewritten != 1 {
		t.Fatalf("objects=%d rewritten=%d, want 1/1", res.Objects, res.Rewritten)
	}
}
