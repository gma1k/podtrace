package agent

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

var errSyntheticApply = stderr("synthetic apply failure")

type stderr string

func (e stderr) Error() string { return string(e) }

func statusApplyClient(t *testing.T, applyErr error, seed ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(seed...).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				return applyErr
			},
		}).Build()
}

func TestStatusWriter_EmitOnce_PatchErrorSurfaces(t *testing.T) {
	router := NewRouter(nil)
	router.Publish([]CRRule{{Key: CRKey{Namespace: "ns", Name: "pt"}}})
	c := statusApplyClient(t, errSyntheticApply)

	w := &StatusWriter{Client: c, NodeName: "n", Router: router, Ready: func() bool { return true }}
	if err := w.emitOnce(context.Background()); err == nil {
		t.Fatal("expected the patch error to surface from emitOnce")
	}
}

func TestStatusWriter_RetractCRStatus_NotFoundIsSwallowed(t *testing.T) {
	notFound := apierrors.NewNotFound(schema.GroupResource{Group: "podtrace.io", Resource: "podtraces"}, "gone")
	c := statusApplyClient(t, notFound)

	w := &StatusWriter{Client: c, NodeName: "n", Router: NewRouter(nil), Ready: func() bool { return true }}

	w.reportedKeys = map[CRKey]struct{}{{Namespace: "ns", Name: "gone"}: {}}

	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("NotFound during retract must be swallowed, got %v", err)
	}
	if _, ok := w.reportedKeys[CRKey{Namespace: "ns", Name: "gone"}]; ok {
		t.Error("retracted key should no longer be tracked")
	}
}

func TestStatusWriter_RetractCRStatus_ErrorSurfaces(t *testing.T) {
	c := statusApplyClient(t, errSyntheticApply)

	w := &StatusWriter{Client: c, NodeName: "n", Router: NewRouter(nil), Ready: func() bool { return true }}
	w.reportedKeys = map[CRKey]struct{}{{Namespace: "ns", Name: "stale"}: {}}

	if err := w.emitOnce(context.Background()); err == nil {
		t.Fatal("expected the non-NotFound retract error to surface")
	}
}

func TestStatusWriter_Run_ApplyErrorLoggedNotFatal(t *testing.T) {
	router := NewRouter(nil)
	router.Publish([]CRRule{{Key: CRKey{Namespace: "ns", Name: "pt"}}})
	c := statusApplyClient(t, errSyntheticApply)

	w := &StatusWriter{
		Client:   c,
		NodeName: "n",
		Router:   router,
		Interval: 5 * time.Millisecond,
		Ready:    func() bool { return true },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := w.Run(ctx); err != nil {
		t.Errorf("Run returned %v despite per-tick apply errors", err)
	}
}

func TestStatusWriter_Run_DefaultIntervalWhenUnset(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	w := &StatusWriter{
		Client:   c,
		NodeName: "n",
		Router:   NewRouter(nil),
		Interval: 0,
		Ready:    func() bool { return true },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
