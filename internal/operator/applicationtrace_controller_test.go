package operator

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func mkApp() *podtracev1alpha1.ApplicationTrace {
	return &podtracev1alpha1.ApplicationTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "demo", UID: "app-uid", Generation: 1},
		Spec: podtracev1alpha1.ApplicationTraceSpec{
			Selectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"app.kubernetes.io/name": "shop", "tier": "web"}},
				{MatchLabels: map[string]string{"app.kubernetes.io/name": "shop", "tier": "api"}},
			},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "default"},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS, podtracev1alpha1.FilterNet},
		},
	}
}

func TestApplicationTraceReconciler_GeneratesOwnedPodTrace(t *testing.T) {
	scheme := newOperatorScheme(t)
	app := mkApp()
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(app).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "demo", Name: "shop"},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var pt podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: "shop"}, &pt); err != nil {
		t.Fatalf("child PodTrace not created: %v", err)
	}

	if pt.Spec.AppSelector == nil || len(pt.Spec.AppSelector.MatchSelectors) != 2 {
		t.Fatalf("child appSelector = %+v, want 2 selectors", pt.Spec.AppSelector)
	}
	if pt.Spec.Selector != nil || len(pt.Spec.PodRefs) != 0 {
		t.Fatalf("child must use appSelector only, got selector=%v podRefs=%v", pt.Spec.Selector, pt.Spec.PodRefs)
	}
	if pt.Spec.ExporterRef.Name != "default" {
		t.Fatalf("exporterRef = %q, want default", pt.Spec.ExporterRef.Name)
	}
	if len(pt.Spec.Filters) != 2 {
		t.Fatalf("filters = %v, want [dns net]", pt.Spec.Filters)
	}

	if len(pt.OwnerReferences) != 1 {
		t.Fatalf("ownerRefs = %v, want 1", pt.OwnerReferences)
	}
	or := pt.OwnerReferences[0]
	if or.Kind != "ApplicationTrace" || or.Name != "shop" || or.Controller == nil || !*or.Controller {
		t.Fatalf("owner ref = %+v, want controller ApplicationTrace/shop", or)
	}
	if pt.Labels[LabelApplication] != "shop" {
		t.Fatalf("missing %s=shop label, got %v", LabelApplication, pt.Labels)
	}

	var got podtracev1alpha1.ApplicationTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: "shop"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.PodTraceRef != "shop" {
		t.Fatalf("status.podTraceRef = %q, want shop", got.Status.PodTraceRef)
	}
	if !hasCond(got.Status.Conditions, ConditionReconciled, metav1.ConditionTrue) {
		t.Fatalf("expected Reconciled=True, conditions=%+v", got.Status.Conditions)
	}
}

func TestApplicationTraceReconciler_AggregatesChildStatus(t *testing.T) {
	scheme := newOperatorScheme(t)
	app := mkApp()
	child := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "demo"},
		Status: podtracev1alpha1.PodTraceStatus{
			MatchedPods:      4,
			TargetNamespaces: []string{"demo", "demo-b"},
			Conditions: []metav1.Condition{{
				Type: ConditionReady, Status: metav1.ConditionTrue, Reason: "AgentsReady",
				LastTransitionTime: metav1.Now(),
			}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(app, child).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "demo", Name: "shop"},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got podtracev1alpha1.ApplicationTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "demo", Name: "shop"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.MatchedPods != 4 {
		t.Fatalf("aggregated matchedPods = %d, want 4", got.Status.MatchedPods)
	}
	if len(got.Status.TargetNamespaces) != 2 {
		t.Fatalf("aggregated targetNamespaces = %v, want 2", got.Status.TargetNamespaces)
	}
	if !hasCond(got.Status.Conditions, ConditionReady, metav1.ConditionTrue) {
		t.Fatalf("Ready should mirror child (True), conditions=%+v", got.Status.Conditions)
	}
}

func hasCond(conds []metav1.Condition, t string, s metav1.ConditionStatus) bool {
	for _, c := range conds {
		if c.Type == t {
			return c.Status == s
		}
	}
	return false
}
