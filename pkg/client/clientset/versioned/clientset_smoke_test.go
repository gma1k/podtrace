package versioned_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	versionedfake "github.com/podtrace/podtrace/pkg/client/clientset/versioned/fake"
)

// TestClientset_CreateListGet_RoundTrip smoke-tests the generated typed
// clientset against its in-memory fake. The fake is generated alongside
// the real clientset and uses the same object tracker under the hood, so
// a happy-path Create/List/Get roundtrip here verifies that every typed
// interface (PodTraces, PodTraceSessions, ExporterConfigs, TracerConfigs)
// was wired correctly by client-gen.
//
// External consumers will use NewForConfig(restCfg) against a real
// cluster; this test covers the generated machinery without one.
func TestClientset_CreateListGet_RoundTrip(t *testing.T) {
	cs := versionedfake.NewSimpleClientset()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const ns = "default"

	// PodTrace
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if _, err := cs.PodtraceV1alpha1().PodTraces(ns).Create(ctx, pt, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create PodTrace: %v", err)
	}
	fetched, err := cs.PodtraceV1alpha1().PodTraces(ns).Get(ctx, "pt", metav1.GetOptions{})
	if err != nil || fetched.Name != "pt" {
		t.Fatalf("get PodTrace: %v fetched=%+v", err, fetched)
	}

	// PodTraceSession
	pts := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if _, err := cs.PodtraceV1alpha1().PodTraceSessions(ns).Create(ctx, pts, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create PodTraceSession: %v", err)
	}

	// ExporterConfig
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318"},
		},
	}
	if _, err := cs.PodtraceV1alpha1().ExporterConfigs(ns).Create(ctx, ec, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ExporterConfig: %v", err)
	}

	// TracerConfig is cluster-scoped.
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/podtrace/podtrace:test"},
	}
	if _, err := cs.PodtraceV1alpha1().TracerConfigs().Create(ctx, tc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create TracerConfig: %v", err)
	}

	// List assertions — each resource type returns one item.
	if list, err := cs.PodtraceV1alpha1().PodTraces(ns).List(ctx, metav1.ListOptions{}); err != nil || len(list.Items) != 1 {
		t.Errorf("list PodTraces: err=%v items=%d", err, len(list.Items))
	}
	if list, err := cs.PodtraceV1alpha1().PodTraceSessions(ns).List(ctx, metav1.ListOptions{}); err != nil || len(list.Items) != 1 {
		t.Errorf("list PodTraceSessions: err=%v items=%d", err, len(list.Items))
	}
	if list, err := cs.PodtraceV1alpha1().ExporterConfigs(ns).List(ctx, metav1.ListOptions{}); err != nil || len(list.Items) != 1 {
		t.Errorf("list ExporterConfigs: err=%v items=%d", err, len(list.Items))
	}
	if list, err := cs.PodtraceV1alpha1().TracerConfigs().List(ctx, metav1.ListOptions{}); err != nil || len(list.Items) != 1 {
		t.Errorf("list TracerConfigs: err=%v items=%d", err, len(list.Items))
	}
}

// TestClientset_DeletePropagates covers the Delete verb for every typed
// interface. The fake's object tracker is strict about kind registration
// — a missing DeepCopyObject on any type would break deletes here.
func TestClientset_DeletePropagates(t *testing.T) {
	ctx := context.Background()
	cs := versionedfake.NewSimpleClientset(
		&podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"}},
		&podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"}},
		&podtracev1alpha1.ExporterConfig{ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "default"}},
		&podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
	)

	if err := cs.PodtraceV1alpha1().PodTraces("default").Delete(ctx, "pt", metav1.DeleteOptions{}); err != nil {
		t.Errorf("delete PodTrace: %v", err)
	}
	if err := cs.PodtraceV1alpha1().PodTraceSessions("default").Delete(ctx, "pts", metav1.DeleteOptions{}); err != nil {
		t.Errorf("delete PodTraceSession: %v", err)
	}
	if err := cs.PodtraceV1alpha1().ExporterConfigs("default").Delete(ctx, "ec", metav1.DeleteOptions{}); err != nil {
		t.Errorf("delete ExporterConfig: %v", err)
	}
	if err := cs.PodtraceV1alpha1().TracerConfigs().Delete(ctx, "default", metav1.DeleteOptions{}); err != nil {
		t.Errorf("delete TracerConfig: %v", err)
	}
}
