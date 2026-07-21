package nodespawn

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestStartPortForward_NilPod(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := StartPortForward(context.Background(), &rest.Config{}, fake.NewClientset(), nil, 8080, 80, &out, &errBuf)
	if err == nil || !strings.Contains(err.Error(), "nil pod") {
		t.Fatalf("expected nil-pod error, got %v", err)
	}
}

func TestStartPortForward_UnreachableFailsToBecomeReady(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "podtrace"}}},
	}
	cs, cfg := newAttachClientset(t, pod)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var out, errBuf bytes.Buffer
	err := StartPortForward(ctx, cfg, cs, pod, 0, 80, &out, &errBuf)
	if err == nil {
		t.Fatalf("expected a portforward error against an unreachable host")
	}
	if !strings.Contains(err.Error(), "did not become ready") &&
		!strings.Contains(err.Error(), "connection refused") &&
		!strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("unexpected portforward error: %v", err)
	}
}
