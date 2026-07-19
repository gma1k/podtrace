package operator

import (
	"context"
	"testing"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s.io/apimachinery/pkg/types"
)

func sessionObservationCount(ns, name string) int {
	observed.Lock()
	defer observed.Unlock()
	n := 0
	for k := range observed.seen {
		if k.Namespace == ns && k.Name == name {
			n++
		}
	}
	return n
}

func TestReconcile_NotFound_ClearsDedupEntry(t *testing.T) {
	const ns, name = "team-a", "ghost"
	observed.Lock()
	observed.seen[reportObservationKey{Namespace: ns, Name: name, Attempts: 1, Succeeded: true}] = struct{}{}
	observed.Unlock()
	defer forgetReportObservations(ns, name)

	if got := sessionObservationCount(ns, name); got != 1 {
		t.Fatalf("precondition: dedup count = %d, want 1", got)
	}

	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	if err != nil {
		t.Fatalf("reconcile error = %v", err)
	}
	if res != (ctrl.Result{}) {
		t.Errorf("result = %+v, want empty", res)
	}
	if got := sessionObservationCount(ns, name); got != 0 {
		t.Errorf("dedup entry leaked: count = %d, want 0 after NotFound reconcile", got)
	}
}
