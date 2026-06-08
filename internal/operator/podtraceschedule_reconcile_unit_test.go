package operator

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// fixedNow is a stable timestamp used across the schedule reconcile tests
// so cron math and history GC never depend on the wall clock.
var fixedScheduleNow = time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

func newScheduleReconciler(t *testing.T, objs ...client.Object) (*PodTraceScheduleReconciler, *runtime.Scheme) {
	t.Helper()
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(objs...).
		Build()
	return &PodTraceScheduleReconciler{
		Client: c,
		Scheme: s,
		nowFn:  func() time.Time { return fixedScheduleNow },
	}, s
}

// TestPodTraceScheduleReconcile_NotFound exercises the IsNotFound exit path:
// a request for a name that does not exist returns an empty result, no error.
func TestPodTraceScheduleReconcile_NotFound(t *testing.T) {
	r, _ := newScheduleReconciler(t)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile(not found) error = %v, want nil", err)
	}
	if res != (ctrl.Result{}) {
		t.Fatalf("Reconcile(not found) result = %+v, want empty", res)
	}
}

// TestPodTraceScheduleReconcile_CreatesSession reconciles a valid schedule and
// asserts a child session is created and status is written back.
func TestPodTraceScheduleReconcile_CreatesSession(t *testing.T) {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "every5",
			Namespace:         "default",
			UID:               "sch-uid-1",
			Generation:        7,
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-24 * time.Hour)),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Metadata: podtracev1alpha1.PodTraceSessionTemplateMetadata{
					Labels:      map[string]string{"team": "obs"},
					Annotations: map[string]string{"note": "scheduled"},
				},
				Spec: podtracev1alpha1.PodTraceSessionSpec{},
			},
		},
	}

	r, _ := newScheduleReconciler(t, sch)
	ctx := context.Background()

	res, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile error = %v, want nil", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("Reconcile RequeueAfter = %v, want > 0", res.RequeueAfter)
	}

	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions, client.InNamespace(sch.Namespace)); err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions.Items) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions.Items))
	}
	child := sessions.Items[0]
	if !isOwnedBy(&child, sch) {
		t.Fatalf("created session %s not owned by schedule", child.Name)
	}
	if child.Labels["podtrace.io/schedule"] != sch.Name {
		t.Errorf("session schedule label = %q, want %q", child.Labels["podtrace.io/schedule"], sch.Name)
	}
	if child.Labels["team"] != "obs" {
		t.Errorf("template label not propagated: %v", child.Labels)
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace}, &got); err != nil {
		t.Fatalf("get schedule: %v", err)
	}
	if got.Status.ObservedGeneration != sch.Generation {
		t.Errorf("ObservedGeneration = %d, want %d", got.Status.ObservedGeneration, sch.Generation)
	}
	if len(got.Status.Conditions) == 0 {
		t.Errorf("expected at least one status condition, got none")
	}
	if got.Status.LastScheduleTime == nil {
		t.Errorf("expected LastScheduleTime to be set after a triggered run")
	}
}

// TestEnsureSessionForRun_And_Ownership covers ensureSessionForRun creating a
// session, listOwnedSessions + isOwnedBy filtering by owner UID.
func TestEnsureSessionForRun_And_Ownership(t *testing.T) {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "owner-sched",
			Namespace: "default",
			UID:       "owner-uid",
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{},
			},
		},
	}

	foreign := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foreign",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: podtracev1alpha1.GroupVersion.String(),
				Kind:       "PodTraceSchedule",
				Name:       "someone-else",
				UID:        "other-uid",
			}},
		},
	}

	r, _ := newScheduleReconciler(t, sch, foreign)
	ctx := context.Background()

	runTime := fixedScheduleNow
	session, created, err := r.ensureSessionForRun(ctx, sch, runTime)
	if err != nil {
		t.Fatalf("ensureSessionForRun error = %v", err)
	}
	if !created {
		t.Fatalf("ensureSessionForRun created = false, want true on first call")
	}
	if !isOwnedBy(session, sch) {
		t.Fatalf("ensured session not owned by schedule")
	}

	_, created2, err := r.ensureSessionForRun(ctx, sch, runTime)
	if err != nil {
		t.Fatalf("ensureSessionForRun (2nd) error = %v", err)
	}
	if created2 {
		t.Errorf("ensureSessionForRun second call created = true, want false (idempotent)")
	}

	owned, err := r.listOwnedSessions(ctx, sch)
	if err != nil {
		t.Fatalf("listOwnedSessions error = %v", err)
	}
	if len(owned) != 1 {
		t.Fatalf("listOwnedSessions returned %d, want 1 (foreign must be filtered)", len(owned))
	}
	if owned[0].Name != session.Name {
		t.Errorf("owned session = %q, want %q", owned[0].Name, session.Name)
	}
}

// TestApplyHistoryLimits_GCOldest builds several completed/failed sessions with
// distinct completion times and asserts gcOldest / applyHistoryLimits keep only
// the newest within the configured limits.
func TestApplyHistoryLimits_GCOldest(t *testing.T) {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gc-sched",
			Namespace: "default",
			UID:       "gc-uid",
		},
	}
	keepSucc := int32(1)
	keepFail := int32(0)
	sch.Spec.SuccessfulSessionsHistoryLimit = &keepSucc
	sch.Spec.FailedSessionsHistoryLimit = &keepFail

	mk := func(name string, state podtracev1alpha1.SessionState, completedAt time.Time) *podtracev1alpha1.PodTraceSession {
		ct := metav1.NewTime(completedAt)
		return &podtracev1alpha1.PodTraceSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: podtracev1alpha1.GroupVersion.String(),
					Kind:       "PodTraceSchedule",
					Name:       sch.Name,
					UID:        sch.UID,
				}},
			},
			Status: podtracev1alpha1.PodTraceSessionStatus{
				State:          state,
				CompletionTime: &ct,
			},
		}
	}

	oldSucc := mk("succ-old", podtracev1alpha1.SessionStateCompleted, fixedScheduleNow.Add(-2*time.Hour))
	newSucc := mk("succ-new", podtracev1alpha1.SessionStateCompleted, fixedScheduleNow.Add(-1*time.Hour))
	fail1 := mk("fail-1", podtracev1alpha1.SessionStateFailed, fixedScheduleNow.Add(-90*time.Minute))
	fail2 := mk("fail-2", podtracev1alpha1.SessionStateFailed, fixedScheduleNow.Add(-30*time.Minute))

	r, _ := newScheduleReconciler(t, sch, oldSucc, newSucc, fail1, fail2)
	ctx := context.Background()

	succeeded := []podtracev1alpha1.PodTraceSession{*oldSucc, *newSucc}
	failed := []podtracev1alpha1.PodTraceSession{*fail1, *fail2}

	if err := r.applyHistoryLimits(ctx, sch, succeeded, failed); err != nil {
		t.Fatalf("applyHistoryLimits error = %v", err)
	}

	owned, err := r.listOwnedSessions(ctx, sch)
	if err != nil {
		t.Fatalf("listOwnedSessions error = %v", err)
	}
	remaining := map[string]bool{}
	for _, s := range owned {
		remaining[s.Name] = true
	}

	if remaining["succ-old"] {
		t.Errorf("succ-old should have been GCed (keep=1)")
	}
	if !remaining["succ-new"] {
		t.Errorf("succ-new should remain (newest within keep=1)")
	}
	if remaining["fail-1"] || remaining["fail-2"] {
		t.Errorf("failed sessions should be fully GCed (keep=0): %v", remaining)
	}

	if err := r.gcOldest(ctx, []podtracev1alpha1.PodTraceSession{*newSucc}, 5); err != nil {
		t.Fatalf("gcOldest no-op error = %v", err)
	}
}

// TestParseSchedule covers the bad-timezone error path and the happy path.
func TestParseSchedule(t *testing.T) {
	r, _ := newScheduleReconciler(t)

	bad := "Not/AZone"
	schBadTZ := &podtracev1alpha1.PodTraceSchedule{
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			TimeZone: &bad,
		},
	}
	if _, _, err := r.parseSchedule(schBadTZ); err == nil {
		t.Errorf("parseSchedule(bad timezone) error = nil, want error")
	}

	good := "UTC"
	schGood := &podtracev1alpha1.PodTraceSchedule{
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			TimeZone: &good,
		},
	}
	parsed, loc, err := r.parseSchedule(schGood)
	if err != nil {
		t.Fatalf("parseSchedule(valid) error = %v, want nil", err)
	}
	if parsed == nil || loc == nil {
		t.Fatalf("parseSchedule(valid) returned nil sched/loc")
	}
	if next := parsed.Next(fixedScheduleNow); !next.After(fixedScheduleNow) {
		t.Errorf("parsed schedule Next = %v, want after %v", next, fixedScheduleNow)
	}
}
