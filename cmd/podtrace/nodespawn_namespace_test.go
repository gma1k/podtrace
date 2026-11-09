package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
)

func TestSpawnSharesTargetNamespace(t *testing.T) {
	targets := []nodespawn.PodRef{{Namespace: "tenant-a", Name: "api"}, {Namespace: "tenant-b", Name: "db"}}
	if !spawnSharesTargetNamespace("tenant-b", targets) {
		t.Error("a spawn namespace that is a traced namespace must be flagged")
	}
	if spawnSharesTargetNamespace(nodespawn.DefaultSpawnNamespace, targets) {
		t.Error("the dedicated spawn namespace must not be flagged")
	}
	if spawnSharesTargetNamespace("tenant-a", nil) {
		t.Error("no targets, nothing to flag")
	}
	warnSpawnInTargetNamespace("tenant-a", targets)
	warnSpawnInTargetNamespace("podtrace-cli", targets)
}

func spawnTargetClientset() *fake.Clientset {
	return fake.NewClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", ContainerID: "containerd://abcdef0123456789",
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	})
}

func TestTheSpawnFlowStopsWhenTheDefaultNamespaceCannotBeCreated(t *testing.T) {
	saveSpawnGlobals(t)
	saveNodespawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	t.Setenv("PODTRACE_SPAWN_NAMESPACE", "")
	localMode = false
	spawnNamespace = ""
	spawnImage = "ghcr.io/gma1k/podtrace:test"
	cs := spawnTargetClientset()
	cs.PrependReactor("create", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, nodespawn.DefaultSpawnNamespace, errors.New("rbac"))
	})
	var podCreates int
	cs.PrependReactor("create", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		podCreates++
		return true, nil, errors.New("unexpected")
	})

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{}, sharedClusterResolver{cs},
		pkgkube.TargetSelection{DefaultNamespace: "shop", Pods: []string{"api"}})
	if !handled || err == nil || !strings.Contains(err.Error(), "kubectl create namespace podtrace-cli") {
		t.Fatalf("handled=%v err=%v; want the namespace remediation", handled, err)
	}
	if podCreates != 0 {
		t.Fatalf("spawn pod created %d time(s) without a spawn namespace", podCreates)
	}
}

func TestAnExplicitSpawnNamespaceIsUsedAsIs(t *testing.T) {
	saveSpawnGlobals(t)
	saveNodespawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	t.Setenv("PODTRACE_SPAWN_NAMESPACE", "")
	localMode = false
	spawnNamespace = "shop"
	spawnImage = "ghcr.io/gma1k/podtrace:test"
	cs := spawnTargetClientset()
	var podNamespace string
	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		podNamespace = a.GetNamespace()
		return true, nil, errors.New("admission denied")
	})

	_, _ = maybeSpawnOnNode(context.Background(), nil, &cobra.Command{}, sharedClusterResolver{cs},
		pkgkube.TargetSelection{DefaultNamespace: "shop", Pods: []string{"api"}})
	if podNamespace != "shop" {
		t.Fatalf("spawn pod namespace = %q, want the explicitly chosen shop", podNamespace)
	}
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "namespaces" {
			t.Fatalf("an explicit spawn namespace must not be created or probed, got %s", a.GetVerb())
		}
	}
}
