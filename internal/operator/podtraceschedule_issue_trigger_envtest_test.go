//go:build envtest
// +build envtest

package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func createIssueEvent(t *testing.T, c client.Client, ns, pod string, id detector.ID, message string, at time.Time) {
	t.Helper()
	ev := alerting.BuildAlertEvent(&alerting.Alert{
		Severity:  alerting.SeverityWarning,
		Source:    alerting.AlertSourceIssue,
		ErrorCode: string(id),
		Title:     message,
		PodName:   pod,
		Namespace: ns,
		Timestamp: at,
	}, at)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Create(ctx, ev); err != nil {
		t.Fatalf("create issue event: %v", err)
	}
}

func ownedSessions(t *testing.T, c client.Client, ns string, sch *podtracev1alpha1.PodTraceSchedule) []podtracev1alpha1.PodTraceSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var list podtracev1alpha1.PodTraceSessionList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	var out []podtracev1alpha1.PodTraceSession
	for i := range list.Items {
		if isOwnedBy(&list.Items[i], sch) {
			out = append(out, list.Items[i])
		}
	}
	return out
}

func TestPodTraceScheduleReconciler_AnIssueTriggerStartsASessionOnlyForItsIssue(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")

	now := time.Now()
	sch := makeSchedule(t, c, ns, "trig-issue", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Schedule = ""
		s.Spec.Trigger = &podtracev1alpha1.TriggerSpec{
			Sources: []podtracev1alpha1.TriggerSource{{
				Kind:        podtracev1alpha1.TriggerSourceIssue,
				MinSeverity: "warning",
				IssueID:     string(detector.IDL7ErrorRate),
			}},
			ConcurrencyPolicy: podtracev1alpha1.AllowConcurrent,
		}
	})
	r := newEnvtestScheduleReconciler(t, c, now)
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: ns}}

	createIssueEvent(t, c, ns, "busy-pod", detector.IDCPUContention, "CPU contention for shop/api", now)
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(ctx, request); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	if got := ownedSessions(t, c, ns, sch); len(got) != 0 {
		t.Fatalf("cpu.contention started %d sessions on a schedule that selects l7.error_rate", len(got))
	}

	createIssueEvent(t, c, ns, "failing-pod", detector.IDL7ErrorRate, "High application error rate for shop/api: 100.0%", now.Add(time.Second))
	reconcileUntil(t, 10*time.Second,
		func() error {
			if n := len(ownedSessions(t, c, ns, sch)); n != 1 {
				return errf("want 1 session for l7.error_rate, have %d", n)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, request)
			return err
		},
	)

	session := ownedSessions(t, c, ns, sch)[0]
	if session.Spec.PodRefs[0].Name != "failing-pod" {
		t.Errorf("session targets %+v, want failing-pod", session.Spec.PodRefs)
	}
	for key, want := range map[string]string{
		AnnotationTriggeredBy:      string(podtracev1alpha1.TriggerSourceIssue),
		alerting.AnnotationIssueID: string(detector.IDL7ErrorRate),
		AnnotationTriggerReason:    "High application error rate for shop/api: 100.0%",
	} {
		if got := session.Annotations[key]; got != want {
			t.Errorf("annotation %s = %q, want %q", key, got, want)
		}
	}
}

func TestTheAPIServerRejectsAnIssueIDOnANonIssueSource(t *testing.T) {
	_, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "trig-bad-issue", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Trigger: &podtracev1alpha1.TriggerSpec{
				Sources: []podtracev1alpha1.TriggerSource{{
					Kind:    podtracev1alpha1.TriggerSourceOOMKill,
					IssueID: string(detector.IDL7ErrorRate),
				}},
			},
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{
					Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "tgt"}},
					Duration:    metav1.Duration{Duration: 10 * time.Second},
					ExporterRef: corev1.LocalObjectReference{Name: "sch-otlp"},
				},
			},
		},
	}
	err := c.Create(ctx, sch)
	if err == nil {
		t.Fatal("a schedule with issueID on an OOMKill source was accepted")
	}
	if !strings.Contains(err.Error(), "issueID applies only to kind Issue") {
		t.Errorf("rejected for another reason: %v", err)
	}

	sch.Spec.Trigger.Sources[0] = podtracev1alpha1.TriggerSource{Kind: podtracev1alpha1.TriggerSourceIssue, IssueID: "made.up"}
	if err := c.Create(ctx, sch); err == nil {
		t.Fatal("a schedule naming an issue id outside the registry was accepted")
	}
}
