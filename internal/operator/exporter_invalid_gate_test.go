package operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func endpointExporter(ns, endpoint string) *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: endpoint},
		},
	}
}

func conditionReason(conds []metav1.Condition, condType string) string {
	if c := meta.FindStatusCondition(conds, condType); c != nil {
		return c.Reason
	}
	return ""
}

func TestPodTraceWithdrawsTheBundleWhenItsExporterConfigIsInvalid(t *testing.T) {
	const sysNS, ns = "podtrace-system", "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-1", Finalizers: []string{FinalizerCleanup}},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: corev1.LocalObjectReference{Name: "ec"},
		},
	}
	ec := endpointExporter(ns, "otel.default.svc:4318")
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}}
	bundleKey := types.NamespacedName{Name: ExporterBundleName(pt.UID), Namespace: sysNS}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := c.Get(context.Background(), bundleKey, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("a valid ExporterConfig must produce a bundle: %v", err)
	}

	var current podtracev1alpha1.ExporterConfig
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(ec), &current); err != nil {
		t.Fatal(err)
	}
	current.Spec.OTLP.Endpoint = "http://168.63.129.16:4318"
	if err := c.Update(context.Background(), &current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := c.Get(context.Background(), bundleKey, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		t.Fatalf("bundle for an invalid ExporterConfig still present (err=%v)", err)
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if reason := conditionReason(got.Status.Conditions, ConditionDegraded); reason != "ExporterInvalid" {
		t.Fatalf("Degraded reason = %q, want ExporterInvalid", reason)
	}
}

func invalidExporterSession(ns string) (*podtracev1alpha1.PodTraceSession, *corev1.Pod) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: "n1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: ns, UID: "uid-s", Finalizers: []string{FinalizerCleanup}},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: corev1.LocalObjectReference{Name: "ec"},
		},
	}
	return s, pod
}

func TestASessionDoesNotLaunchWithAnInvalidExporterConfig(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	s, pod := invalidExporterSession(ns)
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s, pod, defaultTracerConfigObject(), endpointExporter(ns, "http://[fd00:ec2::254]:4318")).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("want a requeue so fixing the ExporterConfig resumes the session")
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got); err != nil {
		t.Fatal(err)
	}
	if reason := conditionReason(got.Status.Conditions, ConditionDegraded); reason != "ExporterInvalid" {
		t.Fatalf("Degraded reason = %q, want ExporterInvalid", reason)
	}
	var bundles corev1.ConfigMapList
	if err := c.List(context.Background(), &bundles); err != nil {
		t.Fatal(err)
	}
	for _, cm := range bundles.Items {
		if cm.Name == SessionBundleName(s.UID) {
			t.Fatalf("session bundle %s/%s written for an invalid ExporterConfig", cm.Namespace, cm.Name)
		}
	}
}

func TestARunningSessionKeepsItsBundleWhenItsExporterConfigTurnsInvalid(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	s, pod := invalidExporterSession(ns)
	s.Status.Jobs = []podtracev1alpha1.SessionJobRef{{Node: "n1", Name: "job-n1"}}
	s.Status.State = podtracev1alpha1.SessionStateRunning
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: SessionBundleName(s.UID), Namespace: sysNS},
		Data:       map[string]string{"endpoint": "otel.default.svc:4318"},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s, pod, existing, defaultTracerConfigObject(), endpointExporter(ns, "http://168.63.129.16:4318")).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	_, _ = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns}})

	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(existing), &cm); err != nil {
		t.Fatalf("running session bundle: %v", err)
	}
	if cm.Data["endpoint"] != "otel.default.svc:4318" {
		t.Fatalf("bundle endpoint = %q, want the last valid one kept", cm.Data["endpoint"])
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got); err != nil {
		t.Fatal(err)
	}
	if reason := conditionReason(got.Status.Conditions, ConditionDegraded); reason != "ExporterInvalid" {
		t.Fatalf("Degraded reason = %q, want ExporterInvalid", reason)
	}
}
