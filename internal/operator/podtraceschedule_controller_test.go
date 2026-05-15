//go:build envtest
// +build envtest

package operator

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func makeSchedule(t *testing.T, c client.Client, ns, name string, mutators ...func(*podtracev1alpha1.PodTraceSchedule)) *podtracev1alpha1.PodTraceSchedule {
	t.Helper()
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule:          "* * * * *", // every minute
			ConcurrencyPolicy: podtracev1alpha1.AllowConcurrent,
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{
					Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "tgt"}},
					Duration:    metav1.Duration{Duration: 10 * time.Second},
					ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "sch-otlp"},
				},
			},
		},
	}
	for _, m := range mutators {
		m(sch)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Create(ctx, sch); err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	sch.CreationTimestamp = metav1.NewTime(time.Now().Add(-2 * time.Minute))
	return sch
}

func newScheduleReconciler(t *testing.T, c client.Client, now time.Time) *PodTraceScheduleReconciler {
	t.Helper()
	scheme, _, _ := setupSharedEnvtest(t)
	return &PodTraceScheduleReconciler{
		Client: c,
		Scheme: scheme,
		nowFn:  func() time.Time { return now },
	}
}

func TestPodTraceScheduleReconciler_RunCreatesSession(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	sch := makeSchedule(t, c, ns, "sch-run")
	now := time.Now()
	r := newScheduleReconciler(t, c, now)

	reconcileUntil(t, 10*time.Second,
		func() error {
			var list podtracev1alpha1.PodTraceSessionList
			if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
				return err
			}
			owned := 0
			for i := range list.Items {
				if isOwnedBy(&list.Items[i], sch) {
					owned++
				}
			}
			if owned < 1 {
				return errf("no owned sessions yet; have %d total", len(list.Items))
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}})
			return err
		},
	)

	var got podtracev1alpha1.PodTraceSchedule
	if err := c.Get(ctx, types.NamespacedName{Name: sch.Name, Namespace: ns}, &got); err != nil {
		t.Fatalf("get schedule: %v", err)
	}
	if got.Status.LastScheduleTime == nil {
		t.Fatal("LastScheduleTime not set after run")
	}
}

func TestPodTraceScheduleReconciler_SuspendNoRun(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	suspended := true
	sch := makeSchedule(t, c, ns, "sch-suspend", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Suspend = &suspended
	})
	r := newScheduleReconciler(t, c, time.Now())

	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range list.Items {
		if isOwnedBy(&s, sch) {
			t.Fatalf("suspended schedule created session %s", s.Name)
		}
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := c.Get(ctx, types.NamespacedName{Name: sch.Name, Namespace: ns}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !hasCondition(got.Status.Conditions, ConditionPaused, metav1.ConditionTrue) {
		t.Fatalf("Paused condition not surfaced: %+v", got.Status.Conditions)
	}
}

func TestPodTraceScheduleReconciler_InvalidScheduleSetsDegraded(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	sch := makeSchedule(t, c, ns, "sch-bad", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Schedule = "this is not cron"
	})
	r := newScheduleReconciler(t, c, time.Now())

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := c.Get(ctx, types.NamespacedName{Name: sch.Name, Namespace: ns}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !hasCondition(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
		t.Fatalf("Degraded condition not set: %+v", got.Status.Conditions)
	}
}

func TestPodTraceScheduleReconciler_ForbidConcurrentBlocks(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	sch := makeSchedule(t, c, ns, "sch-forbid", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.ConcurrencyPolicy = podtracev1alpha1.ForbidConcurrent
	})
	r := newScheduleReconciler(t, c, time.Now())

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list: %v", err)
	}
	owned := 0
	for i := range list.Items {
		if isOwnedBy(&list.Items[i], sch) {
			owned++
		}
	}
	if owned != 1 {
		t.Fatalf("Forbid did not block second run: have %d owned sessions, want 1", owned)
	}
}

func TestPodTraceScheduleReconciler_HistoryLimitsGC(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	limit := int32(1)
	sch := makeSchedule(t, c, ns, "sch-gc", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	r := newScheduleReconciler(t, c, time.Now())

	t1 := metav1.NewTime(time.Now().Add(-2 * time.Minute))
	t2 := metav1.NewTime(time.Now().Add(-1 * time.Minute))
	for i, ct := range []metav1.Time{t1, t2} {
		s := &podtracev1alpha1.PodTraceSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "seed-" + string('a'+rune(i)),
				Namespace: ns,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: podtracev1alpha1.GroupVersion.String(),
					Kind:       "PodTraceSchedule",
					Name:       sch.Name,
					UID:        sch.UID,
					Controller: ptrBool(true),
				}},
			},
			Spec: *sch.Spec.SessionTemplate.Spec.DeepCopy(),
		}
		if err := c.Create(ctx, s); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		s.Status = podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateCompleted,
			CompletionTime: &ct,
		}
		if err := c.Status().Update(ctx, s); err != nil {
			t.Fatalf("status update: %v", err)
		}
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list: %v", err)
	}
	var owned, completed int
	for i := range list.Items {
		if !isOwnedBy(&list.Items[i], sch) {
			continue
		}
		owned++
		if list.Items[i].Status.State == podtracev1alpha1.SessionStateCompleted {
			completed++
		}
	}
	if completed > 1 {
		t.Fatalf("history limit not enforced: %d completed owned sessions remain", completed)
	}
	_ = owned
}

// TestPodTraceScheduleReconciler_MaxActiveSessionsCap verifies the
// safety-valve cap: when in-flight (active) sessions reach the cap,
// the next run is skipped regardless of ConcurrencyPolicy=Allow. The
// Reconciled condition records ActiveLimitReached.
func TestPodTraceScheduleReconciler_MaxActiveSessionsCap(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	cap := int32(2)
	sch := makeSchedule(t, c, ns, "sch-cap", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.ConcurrencyPolicy = podtracev1alpha1.AllowConcurrent
		s.Spec.MaxActiveSessions = &cap
	})

	// Pre-seed 2 children in active state (empty .status.state).
	for i := 0; i < 2; i++ {
		s := &podtracev1alpha1.PodTraceSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cap-active-" + string('a'+rune(i)),
				Namespace: ns,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: podtracev1alpha1.GroupVersion.String(),
					Kind:       "PodTraceSchedule",
					Name:       sch.Name,
					UID:        sch.UID,
					Controller: ptrBool(true),
				}},
			},
			Spec: *sch.Spec.SessionTemplate.Spec.DeepCopy(),
		}
		if err := c.Create(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	r := newScheduleReconciler(t, c, time.Now())
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := c.Get(ctx, types.NamespacedName{Name: sch.Name, Namespace: ns}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	foundActiveLimit := false
	for _, c := range got.Status.Conditions {
		if c.Type == ConditionReconciled && c.Reason == "ActiveLimitReached" {
			foundActiveLimit = true
			break
		}
	}
	if !foundActiveLimit {
		t.Fatalf("ActiveLimitReached condition not surfaced: %+v", got.Status.Conditions)
	}

	// And no new owned session must have been created.
	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list: %v", err)
	}
	owned := 0
	for i := range list.Items {
		if isOwnedBy(&list.Items[i], sch) {
			owned++
		}
	}
	if owned != 2 {
		t.Fatalf("cap not enforced: %d owned sessions, expected 2 (cap respected, no new run)", owned)
	}
}

// TestPodTraceScheduleReconciler_HistoryLimitsGCOnSkippedRun is the
// regression test for the bug where applyHistoryLimits only ran on
// the run path. A suspended schedule (or a Forbid schedule that keeps
// skipping) must still GC older completed children.
func TestPodTraceScheduleReconciler_HistoryLimitsGCOnSkippedRun(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	limit := int32(1)
	suspended := true
	sch := makeSchedule(t, c, ns, "sch-gc-skip", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
		s.Spec.Suspend = &suspended
	})
	r := newScheduleReconciler(t, c, time.Now())

	// Two completed children pre-seeded. The reconcile path taken here
	// is the Suspend early-return; pre-fix it skipped GC entirely.
	t1 := metav1.NewTime(time.Now().Add(-2 * time.Minute))
	t2 := metav1.NewTime(time.Now().Add(-1 * time.Minute))
	for i, ct := range []metav1.Time{t1, t2} {
		s := &podtracev1alpha1.PodTraceSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "skip-seed-" + string('a'+rune(i)),
				Namespace: ns,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: podtracev1alpha1.GroupVersion.String(),
					Kind:       "PodTraceSchedule",
					Name:       sch.Name,
					UID:        sch.UID,
					Controller: ptrBool(true),
				}},
			},
			Spec: *sch.Spec.SessionTemplate.Spec.DeepCopy(),
		}
		if err := c.Create(ctx, s); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		s.Status = podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateCompleted,
			CompletionTime: &ct,
		}
		if err := c.Status().Update(ctx, s); err != nil {
			t.Fatalf("status update: %v", err)
		}
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list: %v", err)
	}
	completed := 0
	for i := range list.Items {
		if !isOwnedBy(&list.Items[i], sch) {
			continue
		}
		if list.Items[i].Status.State == podtracev1alpha1.SessionStateCompleted {
			completed++
		}
	}
	if completed > 1 {
		t.Fatalf("history limit not enforced on Suspend path: %d completed owned sessions remain", completed)
	}
}

func hasCondition(conds []metav1.Condition, t string, s metav1.ConditionStatus) bool {
	for _, c := range conds {
		if c.Type == t && c.Status == s {
			return true
		}
	}
	return false
}

func ptrBool(b bool) *bool { return &b }