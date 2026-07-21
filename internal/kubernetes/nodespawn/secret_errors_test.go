package nodespawn

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestOwnSecretByPod_GetErrorPropagates(t *testing.T) {
	cs := fake.NewClientset()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "spawn", UID: "uid-1"}}
	err := ownSecretByPod(context.Background(), cs, pod, "missing-secret")
	if err == nil {
		t.Fatalf("expected error when the secret does not exist")
	}
	if !IsNotFound(err) {
		t.Errorf("expected a NotFound error, got %v", err)
	}
}

func TestOwnSecretByPod_UpdateErrorPropagates(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "sec"},
	})
	cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("conflict")
	})
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "spawn", UID: "uid-1"}}
	if err := ownSecretByPod(context.Background(), cs, pod, "sec"); err == nil {
		t.Fatalf("expected update error to propagate")
	}
}

func TestDeleteSecret_WrapsNonNotFoundError(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "sec"},
	})
	cs.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver refused delete")
	})
	err := DeleteSecret(context.Background(), cs, "ns1", "sec")
	if err == nil || !strings.Contains(err.Error(), "delete secret ns1/sec") {
		t.Fatalf("expected wrapped delete-secret error, got %v", err)
	}
}
