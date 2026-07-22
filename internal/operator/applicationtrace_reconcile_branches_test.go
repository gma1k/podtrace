package operator

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestApplicationTraceBranch_ReconcileNotFound(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "demo", Name: "missing"},
	})
	if err != nil {
		t.Fatalf("missing ApplicationTrace must reconcile to a clean no-op, got %v", err)
	}
	if res != (ctrl.Result{}) {
		t.Fatalf("missing ApplicationTrace result = %+v, want empty", res)
	}
}

func TestApplicationTraceBranch_ChildErrorAndPatchStatusError(t *testing.T) {
	scheme := newOperatorScheme(t)
	app := mkApp()
	foreign := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: app.Name, Namespace: app.Namespace},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app, foreign).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: app.Namespace, Name: app.Name},
	}); err == nil {
		t.Fatal("adopting a foreign PodTrace must fail, and a failing status write must surface that error")
	}
}

func TestApplicationTraceBranch_EnsureChildCreateError(t *testing.T) {
	scheme := newOperatorScheme(t)
	app := mkApp()
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTrace); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	if _, err := r.ensureChildPodTrace(context.Background(), app); err == nil {
		t.Fatal("a failing PodTrace create-or-update must be surfaced")
	}
}
