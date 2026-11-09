package nodespawn

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestEnsureSpawnNamespaceCreatesAPrivilegedNamespace(t *testing.T) {
	cs := fake.NewClientset()
	if err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace); err != nil {
		t.Fatalf("EnsureSpawnNamespace: %v", err)
	}
	ns, err := cs.CoreV1().Namespaces().Get(context.Background(), DefaultSpawnNamespace, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("namespace not created: %v", err)
	}
	if ns.Labels[podSecurityEnforceLabel] != "privileged" {
		t.Errorf("enforce label = %q, want privileged", ns.Labels[podSecurityEnforceLabel])
	}
	if ns.Labels[LabelManagedBy] != ManagedByValue {
		t.Errorf("managed-by label = %q, want %q", ns.Labels[LabelManagedBy], ManagedByValue)
	}
}

func TestEnsureSpawnNamespaceLeavesAnExistingNamespaceAlone(t *testing.T) {
	existing := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSpawnNamespace, Labels: map[string]string{"team": "sre"}}}
	cs := fake.NewClientset(existing)
	if err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace); err != nil {
		t.Fatalf("EnsureSpawnNamespace: %v", err)
	}
	for _, a := range cs.Actions() {
		if a.GetVerb() == "create" || a.GetVerb() == "update" || a.GetVerb() == "patch" {
			t.Errorf("unexpected %s on an existing namespace", a.GetVerb())
		}
	}
}

func TestEnsureSpawnNamespaceTrustsANamespaceItMayNotRead(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, DefaultSpawnNamespace, errors.New("rbac"))
	})
	if err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace); err != nil {
		t.Fatalf("EnsureSpawnNamespace: %v", err)
	}
}

func TestEnsureSpawnNamespaceExplainsAForbiddenCreate(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, DefaultSpawnNamespace, errors.New("rbac"))
	})
	err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace)
	if err == nil {
		t.Fatal("want an error when the namespace is missing and cannot be created")
	}
	for _, want := range []string{"kubectl create namespace podtrace-cli", "pod-security.kubernetes.io/enforce=privileged", "--spawn-namespace"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestEnsureSpawnNamespaceToleratesACreateRace(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "namespaces"}, DefaultSpawnNamespace)
	})
	if err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace); err != nil {
		t.Fatalf("EnsureSpawnNamespace: %v", err)
	}
}

func TestEnsureSpawnNamespaceSurfacesOtherErrors(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver down")
	})
	if err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace); err == nil || !strings.Contains(err.Error(), "apiserver down") {
		t.Fatalf("err = %v, want the get failure", err)
	}
	cs2 := fake.NewClientset()
	cs2.PrependReactor("create", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("etcd full")
	})
	if err := EnsureSpawnNamespace(context.Background(), cs2, DefaultSpawnNamespace); err == nil || !strings.Contains(err.Error(), "etcd full") {
		t.Fatalf("err = %v, want the create failure", err)
	}
}
