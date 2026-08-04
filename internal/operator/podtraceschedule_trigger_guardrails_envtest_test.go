//go:build envtest
// +build envtest

package operator

import (
	"context"
	"sort"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/alerting"
)

func ownedSessionNames(t *testing.T, c client.Client, ns string, sch *podtracev1alpha1.PodTraceSchedule) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	names := []string{}
	for i := range list.Items {
		if isOwnedBy(&list.Items[i], sch) {
			names = append(names, list.Items[i].Name)
		}
	}
	sort.Strings(names)
	return names
}

func reloadSchedule(t *testing.T, c client.Client, ns, name string) *podtracev1alpha1.PodTraceSchedule {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var got podtracev1alpha1.PodTraceSchedule
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &got); err != nil {
		t.Fatalf("get schedule: %v", err)
	}
	return &got
}

func reconciledReason(t *testing.T, c client.Client, ns, name string) string {
	t.Helper()
	got := reloadSchedule(t, c, ns, name)
	cond := findCondition(got.Status.Conditions, ConditionReconciled)
	if cond == nil {
		t.Fatalf("no %s condition on %s/%s: %+v", ConditionReconciled, ns, name, got.Status.Conditions)
		return ""
	}
	return cond.Reason
}

func reconcileOnce(t *testing.T, r *PodTraceScheduleReconciler, ns, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func makeTriggerSchedule(t *testing.T, c client.Client, ns, name string, mutate func(*podtracev1alpha1.TriggerSpec)) *podtracev1alpha1.PodTraceSchedule {
	t.Helper()
	return makeSchedule(t, c, ns, name, func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Schedule = ""
		trigger := &podtracev1alpha1.TriggerSpec{
			Sources: []podtracev1alpha1.TriggerSource{
				{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "warning"},
			},
		}
		if mutate != nil {
			mutate(trigger)
		}
		s.Spec.Trigger = trigger
	})
}

func TestPodTraceScheduleReconciler_TriggerRateCap(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ensureExporterConfig(t, c, ns, "sch-otlp")

	now := time.Now()
	maxPerHour := int32(2)
	cooldown := metav1.Duration{Duration: time.Second}
	sch := makeTriggerSchedule(t, c, ns, "trig-ratecap", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Cooldown = &cooldown
		tr.MaxSessionsPerHour = &maxPerHour
		tr.ConcurrencyPolicy = podtracev1alpha1.AllowConcurrent
	})
	r := newEnvtestScheduleReconciler(t, c, now)

	for i, pod := range []string{"hog-a", "hog-b", "hog-c"} {
		createAlertEvent(t, c, ns, pod, alerting.AlertSourceResourceMonitor, "critical",
			now.Add(-time.Duration(3-i)*time.Minute))
	}

	reconcileOnce(t, r, ns, sch.Name)

	names := ownedSessionNames(t, c, ns, sch)
	if len(names) != 2 {
		t.Fatalf("maxSessionsPerHour=2 must cap the pass at 2 sessions, got %d: %v", len(names), names)
		return
	}
	if reason := reconciledReason(t, c, ns, sch.Name); reason != "RateLimited" {
		t.Errorf("condition reason = %q, want RateLimited", reason)
	}

	got := reloadSchedule(t, c, ns, sch.Name)
	if got.Status.Trigger == nil || len(got.Status.Trigger.RecentFirings) != 2 {
		t.Fatalf("status must record exactly 2 firings, got %+v", got.Status.Trigger)
		return
	}

	reconcileOnce(t, r, ns, sch.Name)
	if after := ownedSessionNames(t, c, ns, sch); len(after) != 2 {
		t.Errorf("rolling-hour cap must hold across reconciles, got %d: %v", len(after), after)
	}
}

func TestPodTraceScheduleReconciler_TriggerForbidsConcurrentSessions(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ensureExporterConfig(t, c, ns, "sch-otlp")

	now := time.Now()
	cooldown := metav1.Duration{Duration: time.Second}
	sch := makeTriggerSchedule(t, c, ns, "trig-forbid", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Cooldown = &cooldown
		tr.ConcurrencyPolicy = podtracev1alpha1.ForbidConcurrent
	})
	r := newEnvtestScheduleReconciler(t, c, now)

	createAlertEvent(t, c, ns, "hog-a", alerting.AlertSourceResourceMonitor, "critical", now.Add(-5*time.Minute))
	reconcileOnce(t, r, ns, sch.Name)

	first := ownedSessionNames(t, c, ns, sch)
	if len(first) != 1 {
		t.Fatalf("first alert must fire exactly 1 session, got %d: %v", len(first), first)
		return
	}

	createAlertEvent(t, c, ns, "hog-b", alerting.AlertSourceResourceMonitor, "critical", now.Add(-1*time.Minute))
	reconcileOnce(t, r, ns, sch.Name)

	second := ownedSessionNames(t, c, ns, sch)
	if len(second) != 1 || second[0] != first[0] {
		t.Errorf("Forbid must suppress a new session while one is active, got %v", second)
	}
	if reason := reconciledReason(t, c, ns, sch.Name); reason != "Forbidden" {
		t.Errorf("condition reason = %q, want Forbidden", reason)
	}
}

func TestPodTraceScheduleReconciler_TriggerReplacesActiveSession(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ensureExporterConfig(t, c, ns, "sch-otlp")

	now := time.Now()
	cooldown := metav1.Duration{Duration: time.Second}
	sch := makeTriggerSchedule(t, c, ns, "trig-replace", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Cooldown = &cooldown
		tr.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent
	})
	r := newEnvtestScheduleReconciler(t, c, now)

	createAlertEvent(t, c, ns, "hog-a", alerting.AlertSourceResourceMonitor, "critical", now.Add(-5*time.Minute))
	reconcileOnce(t, r, ns, sch.Name)

	first := ownedSessionNames(t, c, ns, sch)
	if len(first) != 1 {
		t.Fatalf("first alert must fire exactly 1 session, got %d: %v", len(first), first)
		return
	}

	createAlertEvent(t, c, ns, "hog-b", alerting.AlertSourceResourceMonitor, "critical", now.Add(-1*time.Minute))
	reconcileOnce(t, r, ns, sch.Name)

	second := ownedSessionNames(t, c, ns, sch)
	if len(second) != 1 {
		t.Fatalf("Replace must leave exactly 1 session, got %d: %v", len(second), second)
		return
	}
	if second[0] == first[0] {
		t.Errorf("Replace must delete the active session and create a new one, still have %q", second[0])
	}
	if reason := reconciledReason(t, c, ns, sch.Name); reason != "Triggered" {
		t.Errorf("condition reason = %q, want Triggered", reason)
	}
}

func TestPodTraceScheduleReconciler_TriggerSuspendedDoesNotFire(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ensureExporterConfig(t, c, ns, "sch-otlp")

	now := time.Now()
	suspend := true
	sch := makeSchedule(t, c, ns, "trig-suspend", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Schedule = ""
		s.Spec.Suspend = &suspend
		s.Spec.Trigger = &podtracev1alpha1.TriggerSpec{
			Sources: []podtracev1alpha1.TriggerSource{
				{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "warning"},
			},
		}
	})
	r := newEnvtestScheduleReconciler(t, c, now)

	createAlertEvent(t, c, ns, "hog-a", alerting.AlertSourceResourceMonitor, "critical", now)
	reconcileOnce(t, r, ns, sch.Name)

	if names := ownedSessionNames(t, c, ns, sch); len(names) != 0 {
		t.Errorf("a suspended trigger must not fire, got %v", names)
	}
	if reason := reconciledReason(t, c, ns, sch.Name); reason != "Suspended" {
		t.Errorf("condition reason = %q, want Suspended", reason)
	}
}
