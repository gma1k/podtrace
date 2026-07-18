package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestFinalizerUpdateOutcome(t *testing.T) {
	notFound := apierrors.NewNotFound(schema.GroupResource{Group: "podtrace.io", Resource: "podtraces"}, "x")
	conflict := apierrors.NewConflict(schema.GroupResource{Group: "podtrace.io", Resource: "podtraces"}, "x", errors.New("boom"))
	other := errors.New("real failure")

	if res, handled := finalizerUpdateOutcome(notFound); !handled || res.RequeueAfter != 0 {
		t.Errorf("NotFound: got (%v, %v), want ({}, true)", res, handled)
	}
	if res, handled := finalizerUpdateOutcome(conflict); !handled || res.RequeueAfter != time.Second {
		t.Errorf("Conflict: got (%v, %v), want (requeue 1s, true)", res, handled)
	}
	if _, handled := finalizerUpdateOutcome(other); handled {
		t.Errorf("real error must not be swallowed")
	}
}

func TestSessionReconcile_FinalizerClearNotFoundIsClean(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := metav1.Now()
	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "dying",
			Namespace:         "team-a",
			UID:               "u-dying-000",
			DeletionTimestamp: &now,
			Finalizers:        []string{FinalizerCleanup},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return apierrors.NewNotFound(
						schema.GroupResource{Group: "podtrace.io", Resource: "podtracesessions"}, obj.GetName())
				}
				return cl.Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Namespace: "team-a", Name: "dying"},
	})
	if err != nil {
		t.Fatalf("finalizer-clear NotFound must not surface as a reconcile error, got: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("expected no requeue on a completed deletion, got %v", res.RequeueAfter)
	}
}
