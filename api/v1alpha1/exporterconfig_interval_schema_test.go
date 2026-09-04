//go:build envtest
// +build envtest

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func intervalObject(name, interval string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("podtrace.io/v1alpha1")
	u.SetKind("ExporterConfig")
	u.SetName(name)
	u.SetNamespace("interval-schema")
	u.Object["spec"] = map[string]any{
		"type": "otlp",
		"otlp": map[string]any{
			"endpoint": "http://collector.observability:4318",
			"metrics": map[string]any{
				"enabled":  true,
				"interval": interval,
			},
		},
	}
	return u
}

func TestEnvtest_MetricsIntervalMustBeANonNegativeDuration(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "interval-schema"}}
	if err := h.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	for _, bad := range []string{"soon", "-30s", "-1m", "5", "1x", "abc"} {
		t.Run("reject/"+bad, func(t *testing.T) {
			err := h.client.Create(ctx, intervalObject("bad-"+strings.NewReplacer("-", "n", ".", "d").Replace(bad), bad))
			if err == nil {
				t.Fatalf("the API server stored interval %q. metav1.Duration is a string on the "+
					"wire and fails to decode when it is not a duration, so a stored %q breaks "+
					"the typed LIST every client-go informer performs — which stops "+
					"ExporterConfig reconciliation cluster-wide until the object is deleted, "+
					"from one typo in one namespace", bad, bad)
			}
			if !strings.Contains(err.Error(), "non-negative Go duration") {
				t.Errorf("interval %q was rejected with %q, want the schema's own message; a "+
					"rejection from somewhere else would not survive the rule being removed",
					bad, err)
			}
		})
	}

	for _, good := range []string{"10s", "1m", "90s", "1m30s", "500ms", "1.5h", "2h45m", "0"} {
		t.Run("accept/"+good, func(t *testing.T) {
			if err := h.client.Create(ctx, intervalObject("ok-"+strings.NewReplacer(".", "d", "-", "n").Replace(good), good)); err != nil {
				t.Errorf("interval %q was rejected: %v", good, err)
			}
		})
	}
}
