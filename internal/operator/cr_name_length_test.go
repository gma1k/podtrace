package operator

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestValidateManagedCRName(t *testing.T) {
	if err := validateManagedCRName("PodTrace", strings.Repeat("a", 63)); err != nil {
		t.Errorf("63-char name rejected: %v", err)
	}
	if err := validateManagedCRName("PodTrace", strings.Repeat("a", 64)); err == nil {
		t.Error("64-char name accepted, want rejected")
	}
	if err := validateManagedCRName("PodTrace", ""); err != nil {
		t.Errorf("empty name rejected: %v", err)
	}
}

func TestPodTraceReconciler_RejectsTooLongName(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("a", 64)
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo", Finalizers: []string{FinalizerCleanup}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pt).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected terminal (no requeue), got %+v", res)
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "NameTooLong" {
		t.Fatalf("Ready condition = %+v, want False/NameTooLong", cond)
	}
}

func TestPodTraceReconciler_RejectsTooLongExporterConfigName(t *testing.T) {
	scheme := newOperatorScheme(t)
	ecName := strings.Repeat("e", 64)
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "demo", Finalizers: []string{FinalizerCleanup}},
		Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: corev1.LocalObjectReference{Name: ecName}},
	}
	ec := &podtracev1alpha1.ExporterConfig{ObjectMeta: metav1.ObjectMeta{Name: ecName, Namespace: "demo"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pt, ec).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}, &podtracev1alpha1.ExporterConfig{}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: "pt"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected terminal (no requeue), got %+v", res)
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: "pt"}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ExporterConfigNameTooLong" {
		t.Fatalf("Ready condition = %+v, want False/ExporterConfigNameTooLong", cond)
	}
}

func TestPodTraceSessionReconciler_RejectsTooLongName(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("s", 64)
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo", Finalizers: []string{FinalizerCleanup}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected terminal (no requeue loop), got %+v", res)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Fatalf("state = %q, want Failed (terminal, so TTL-GC runs)", got.Status.State)
	}
	cond := findCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "NameTooLong" {
		t.Fatalf("Degraded condition = %+v, want reason NameTooLong", cond)
	}
}

func TestApplicationTraceReconciler_RejectsTooLongName(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("a", 64)
	app := &podtracev1alpha1.ApplicationTrace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(app).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %+v", res)
	}
	var child podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: name}, &child); !apierrors.IsNotFound(err) {
		t.Fatalf("child PodTrace must not be created for an over-long name, got err=%v", err)
	}
	var got podtracev1alpha1.ApplicationTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "NameTooLong" {
		t.Fatalf("Ready condition = %+v, want False/NameTooLong", cond)
	}
}

func TestExporterConfigReconciler_RejectsTooLongName(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("e", 64)
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo", Generation: 1},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "http://collector:4318"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got podtracev1alpha1.ExporterConfig
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "NameTooLong" {
		t.Fatalf("Ready condition = %+v, want False/NameTooLong", cond)
	}
}
