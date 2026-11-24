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

func TestEnsureSpawnNamespaceLeavesAnExistingPodtraceNamespaceAlone(t *testing.T) {
	existing := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSpawnNamespace, Labels: map[string]string{LabelManagedBy: ManagedByValue}}}
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

func TestEnsureSpawnNamespaceRefusesANamespacePodtraceDidNotCreate(t *testing.T) {
	existing := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSpawnNamespace, Labels: map[string]string{"team": "sre"}}}
	cs := fake.NewClientset(existing)
	err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace)
	if err == nil {
		t.Fatal("an unlabelled pre-existing spawn namespace must not be trusted")
	}
	for _, want := range []string{"kubectl label ns/podtrace-cli app.kubernetes.io/managed-by=podtrace-cli", "--spawn-namespace=podtrace-cli"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	for _, a := range cs.Actions() {
		if a.GetVerb() != "get" {
			t.Errorf("unexpected %s on a refused namespace", a.GetVerb())
		}
	}
}

func TestEnsureSpawnNamespaceRefusesATenantNamespaceEvenWhenLabelled(t *testing.T) {
	cases := map[string]metav1.ObjectMeta{
		"capsule owner reference": {OwnerReferences: []metav1.OwnerReference{{Kind: "Tenant", Name: "acme"}}},
		"capsule label":           {Labels: map[string]string{"capsule.clastix.io/tenant": "acme"}},
		"hnc subnamespace":        {Annotations: map[string]string{"hnc.x-k8s.io/subnamespace-of": "acme"}},
		"rancher project":         {Annotations: map[string]string{"field.cattle.io/projectId": "c-1:p-2"}},
	}
	for name, meta := range cases {
		t.Run(name, func(t *testing.T) {
			meta.Name = DefaultSpawnNamespace
			if meta.Labels == nil {
				meta.Labels = map[string]string{}
			}
			meta.Labels[LabelManagedBy] = ManagedByValue
			cs := fake.NewClientset(&corev1.Namespace{ObjectMeta: meta})
			err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace)
			if err == nil || !strings.Contains(err.Error(), "belongs to a tenant") {
				t.Fatalf("err = %v, want a tenant refusal", err)
			}
		})
	}
}

func TestEnsureSpawnNamespaceRefusesANamespaceItMayNotRead(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, DefaultSpawnNamespace, errors.New("rbac"))
	})
	err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace)
	if err == nil || !strings.Contains(err.Error(), "--spawn-namespace=podtrace-cli") {
		t.Fatalf("err = %v, want a refusal naming the explicit flag", err)
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
	for _, want := range []string{"kubectl create namespace podtrace-cli", "pod-security.kubernetes.io/enforce=privileged app.kubernetes.io/managed-by=podtrace-cli", "--spawn-namespace"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func raceCreate(cs *fake.Clientset, winner *corev1.Namespace) {
	cs.PrependReactor("create", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		if winner != nil {
			_ = cs.Tracker().Add(winner)
		}
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "namespaces"}, DefaultSpawnNamespace)
	})
}

func TestEnsureSpawnNamespaceToleratesACreateRaceWithAnotherPodtrace(t *testing.T) {
	cs := fake.NewClientset()
	raceCreate(cs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSpawnNamespace, Labels: map[string]string{LabelManagedBy: ManagedByValue}}})
	if err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace); err != nil {
		t.Fatalf("EnsureSpawnNamespace: %v", err)
	}
}

func TestEnsureSpawnNamespaceRefusesACreateRaceWonBySomeoneElse(t *testing.T) {
	cs := fake.NewClientset()
	raceCreate(cs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSpawnNamespace}})
	if err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace); err == nil {
		t.Fatal("a namespace another party created in the race must not be trusted")
	}
}

func TestEnsureSpawnNamespaceReportsARacedNamespaceItCannotRead(t *testing.T) {
	cs := fake.NewClientset()
	raceCreate(cs, nil)
	err := EnsureSpawnNamespace(context.Background(), cs, DefaultSpawnNamespace)
	if err == nil || !strings.Contains(err.Error(), "created concurrently") {
		t.Fatalf("err = %v, want the concurrent-create failure", err)
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
