package agent

import (
	"context"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	podtraceac "github.com/gma1k/podtrace/pkg/client/applyconfiguration/api/v1alpha1"
)

func podTraceWithRows(name string, nodes ...string) *podtracev1alpha1.PodTrace {
	pt := &podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}}
	for _, n := range nodes {
		pt.Status.NodeStatus = append(pt.Status.NodeStatus, podtracev1alpha1.PodTraceNodeStatus{Node: n})
	}
	return pt
}

type applyRecorder struct {
	retracted []string
	patched   []string
}

func (a *applyRecorder) client(t *testing.T, objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, obj runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				ac := obj.(*podtraceac.PodTraceApplyConfiguration)
				if ac.Status != nil && len(ac.Status.NodeStatus) > 0 {
					a.patched = append(a.patched, *ac.Name)
				} else {
					a.retracted = append(a.retracted, *ac.Name)
				}
				return nil
			},
		}).Build()
}

func TestStatusWriter_RetractsRowsLeftByAnEarlierAgentRun(t *testing.T) {
	rec := &applyRecorder{}
	c := rec.client(t,
		podTraceWithRows("stale", "n", "other"),
		podTraceWithRows("active", "n"),
		podTraceWithRows("foreign", "other"),
	)
	router := NewRouter(nil)
	router.Publish([]CRRule{{Key: CRKey{Namespace: "ns", Name: "active"}}})
	w := &StatusWriter{Client: c, NodeName: "n", Router: router, Ready: func() bool { return true }}

	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}
	sort.Strings(rec.retracted)
	if len(rec.retracted) != 1 || rec.retracted[0] != "stale" {
		t.Errorf("retracted = %v, want only the CR this node no longer matches", rec.retracted)
	}
	if len(rec.patched) != 1 || rec.patched[0] != "active" {
		t.Errorf("patched = %v, want the active CR", rec.patched)
	}

	rec.retracted = nil
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("second emitOnce: %v", err)
	}
	if len(rec.retracted) != 0 {
		t.Errorf("second tick retracted %v again; the row is gone", rec.retracted)
	}
}

func TestStatusWriter_DoesNotSweepBeforeTheFirstReconcile(t *testing.T) {
	rec := &applyRecorder{}
	c := rec.client(t, podTraceWithRows("pending", "n"))
	w := &StatusWriter{Client: c, NodeName: "n", Router: NewRouter(nil), Ready: func() bool { return true }}

	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}
	if len(rec.retracted) != 0 {
		t.Errorf("retracted %v before any rule set was published", rec.retracted)
	}
	if w.swept {
		t.Error("sweep must wait for the first published rule set")
	}
}

func TestStatusWriter_SweepIsRetriedWhenTheListFails(t *testing.T) {
	listFails := true
	retracted := 0
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(podTraceWithRows("stale", "n")).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if listFails {
					return errSyntheticApply
				}
				return cl.List(ctx, list, opts...)
			},
			SubResourceApply: func(context.Context, client.Client, string, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
				retracted++
				return nil
			},
		}).Build()
	router := NewRouter(nil)
	router.Publish(nil)
	w := &StatusWriter{Client: c, NodeName: "n", Router: router, Ready: func() bool { return true }}

	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}
	if w.swept || retracted != 0 {
		t.Fatalf("swept=%v retracted=%d after a failed list, want neither", w.swept, retracted)
	}
	listFails = false
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}
	if !w.swept || retracted != 1 {
		t.Errorf("swept=%v retracted=%d, want the sweep to run on the next tick", w.swept, retracted)
	}
}
