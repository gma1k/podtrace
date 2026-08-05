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

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
)

func createAlertEvent(t *testing.T, c client.Client, ns, pod, source, severity string, at time.Time) {
	t.Helper()
	ev := alerting.BuildAlertEvent(&alerting.Alert{
		Severity:  alerting.AlertSeverity(severity),
		Source:    source,
		Title:     "test alert",
		PodName:   pod,
		Namespace: ns,
		Timestamp: at,
	}, at)
	if ev == nil {
		t.Fatal("BuildAlertEvent returned nil for a pod-bearing alert")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Create(ctx, ev); err != nil {
		t.Fatalf("create alert event: %v", err)
	}
}

func ownedSessionCount(t *testing.T, c client.Client, ns string, sch *podtracev1alpha1.PodTraceSchedule) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	n := 0
	for i := range list.Items {
		if isOwnedBy(&list.Items[i], sch) {
			n++
		}
	}
	return n
}

func TestPodTraceScheduleReconciler_TriggerFiresOneSessionPerCooldown(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	now := time.Now()
	sch := makeSchedule(t, c, ns, "trig-cooldown", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Schedule = ""
		cd := metav1.Duration{Duration: time.Hour}
		s.Spec.Trigger = &podtracev1alpha1.TriggerSpec{
			Sources:           []podtracev1alpha1.TriggerSource{{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "warning"}},
			Cooldown:          &cd,
			ConcurrencyPolicy: podtracev1alpha1.AllowConcurrent,
		}
	})
	r := newEnvtestScheduleReconciler(t, c, now)

	createAlertEvent(t, c, ns, "victim-pod", alerting.AlertSourceResourceMonitor, "critical", now)
	reconcileUntil(t, 10*time.Second,
		func() error {
			if n := ownedSessionCount(t, c, ns, sch); n != 1 {
				return errf("want 1 owned session after first alert, have %d", n)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}})
			return err
		},
	)

	createAlertEvent(t, c, ns, "victim-pod", alerting.AlertSourceResourceMonitor, "critical", now.Add(time.Minute))
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	if n := ownedSessionCount(t, c, ns, sch); n != 1 {
		t.Fatalf("cooldown must suppress the second alert: want 1 session, have %d", n)
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := c.Get(ctx, types.NamespacedName{Name: sch.Name, Namespace: ns}, &got); err != nil {
		t.Fatalf("get schedule: %v", err)
	}
	if got.Status.Trigger == nil || len(got.Status.Trigger.RecentFirings) != 1 {
		t.Fatalf("status should record exactly one firing, got %+v", got.Status.Trigger)
		return
	}
	if got.Status.Trigger.RecentFirings[0].PodName != "victim-pod" {
		t.Errorf("firing should record the alerting pod, got %q", got.Status.Trigger.RecentFirings[0].PodName)
	}
}

func TestPodTraceScheduleReconciler_TriggerTargetsAlertingPod(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	now := time.Now()
	sch := makeSchedule(t, c, ns, "trig-target", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Schedule = ""
		s.Spec.Trigger = &podtracev1alpha1.TriggerSpec{
			Sources: []podtracev1alpha1.TriggerSource{{Kind: podtracev1alpha1.TriggerSourceOOMKill, MinSeverity: "warning"}},
		}
	})
	r := newEnvtestScheduleReconciler(t, c, now)

	createAlertEvent(t, c, ns, "doomed-pod", alerting.AlertSourceOOM, "fatal", now)
	reconcileUntil(t, 10*time.Second,
		func() error {
			if n := ownedSessionCount(t, c, ns, sch); n != 1 {
				return errf("want 1 session, have %d", n)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}})
			return err
		},
	)

	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list: %v", err)
	}
	var session *podtracev1alpha1.PodTraceSession
	for i := range list.Items {
		if isOwnedBy(&list.Items[i], sch) {
			session = &list.Items[i]
			break
		}
	}
	if session == nil {
		t.Fatal("no owned session")
		return
	}
	if len(session.Spec.PodRefs) != 1 || session.Spec.PodRefs[0].Name != "doomed-pod" {
		t.Errorf("session should target the alerting pod via PodRefs, got %+v", session.Spec.PodRefs)
	}
	if session.Spec.Selector != nil {
		t.Error("triggered session should clear the template selector in favor of the pod ref")
	}
	if session.Annotations["podtrace.io/triggered-by"] != string(podtracev1alpha1.TriggerSourceOOMKill) {
		t.Errorf("session missing triggered-by annotation, got %q", session.Annotations["podtrace.io/triggered-by"])
	}
}
