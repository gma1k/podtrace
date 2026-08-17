package operator

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

var pendingDeadlineCreated = metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

func newPendingDeadlineReconciler(t *testing.T, at time.Time) (*PodTraceSessionReconciler, *fakeGetter) {
	t.Helper()
	scheme := newOperatorScheme(t)
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.CreationTimestamp = pendingDeadlineCreated })
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()
	r := &PodTraceSessionReconciler{
		Client:          c,
		Scheme:          scheme,
		SystemNamespace: sessMoreSysNS,
		nowFn:           func() time.Time { return at },
	}
	return r, &fakeGetter{r: r}
}

type fakeGetter struct{ r *PodTraceSessionReconciler }

func (g *fakeGetter) session(t *testing.T) podtracev1alpha1.PodTraceSession {
	t.Helper()
	var got podtracev1alpha1.PodTraceSession
	if err := g.r.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "default"}, &got); err != nil {
		t.Fatalf("get session: %v", err)
	}
	return got
}

func TestSessionReconcile_ZeroMatchPastDeadlineFailsTerminally(t *testing.T) {
	r, g := newPendingDeadlineReconciler(t, pendingDeadlineCreated.Add(pendingMatchDeadline+time.Minute))

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("terminal failure must not return an error, got %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("a terminally failed session must not requeue, got %v", res.RequeueAfter)
	}

	got := g.session(t)
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Fatalf("state = %q, want Failed", got.Status.State)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "NoMatchedPodsDeadlineExceeded" {
		t.Fatalf("degraded condition = %+v, want reason NoMatchedPodsDeadlineExceeded", cond)
	}
}

func TestSessionReconcile_ZeroMatchBeforeDeadlineStaysPending(t *testing.T) {
	r, g := newPendingDeadlineReconciler(t, pendingDeadlineCreated.Add(pendingMatchDeadline-time.Minute))

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("a still-pending session must requeue to re-check for matched pods")
	}

	got := g.session(t)
	if got.Status.State != podtracev1alpha1.SessionStatePending {
		t.Fatalf("state = %q, want Pending", got.Status.State)
	}
}
