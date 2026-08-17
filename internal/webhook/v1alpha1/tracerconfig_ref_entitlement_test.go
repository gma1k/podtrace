package v1alpha1

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func entitlementClient(t *testing.T, config *podtracev1alpha1.TracerConfig) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(config).Build()
}

func TestResolveTracerConfigRef_CrossTenantWithoutConsentRejected(t *testing.T) {
	config := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "regulated"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "img", SystemNamespace: "fleet-b"},
	}
	c := entitlementClient(t, config)

	err := resolveTracerConfigRef(context.Background(), c, &podtracev1alpha1.LocalObjectReference{Name: "regulated"}, "team-a", "podtrace-system")
	if err == nil {
		t.Fatal("a cross-tenant pin without consent must be rejected at admission")
	}
	if !strings.Contains(err.Error(), podtracev1alpha1.AllowSessionsFromAnnotation) {
		t.Errorf("error should name the consent annotation, got %q", err)
	}
}

func TestResolveTracerConfigRef_CrossTenantWithConsentAccepted(t *testing.T) {
	config := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "regulated",
			Annotations: map[string]string{podtracev1alpha1.AllowSessionsFromAnnotation: "team-a"},
		},
		Spec: podtracev1alpha1.TracerConfigSpec{Image: "img", SystemNamespace: "fleet-b"},
	}
	c := entitlementClient(t, config)

	if err := resolveTracerConfigRef(context.Background(), c, &podtracev1alpha1.LocalObjectReference{Name: "regulated"}, "team-a", "podtrace-system"); err != nil {
		t.Fatalf("a consented cross-tenant pin must pass admission, got %v", err)
	}
}
