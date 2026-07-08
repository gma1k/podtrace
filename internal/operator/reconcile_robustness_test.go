package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestLabelSelectorToFlag_MatchExpressions is a regression test: only
// MatchLabels were serialized, so an expression-only selector became an
// empty string — which combined with --all-in-namespace traced every pod in
// the namespace.
func TestLabelSelectorToFlag_MatchExpressions(t *testing.T) {
	flag := labelSelectorToFlag(&metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "api"},
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "worker"},
		}},
	})
	if !strings.Contains(flag, "app=api") || !strings.Contains(flag, "tier in (web,worker)") {
		t.Errorf("flag = %q, want both matchLabels and matchExpressions serialized", flag)
	}

	exprOnly := labelSelectorToFlag(&metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "team", Operator: metav1.LabelSelectorOpExists,
		}},
	})
	if exprOnly == "" {
		t.Error("expression-only selector must not serialize to an empty string")
	}
}

// TestComputeSessionState_UndercountedJobsNotTerminal: the Job List comes
// from the informer cache and may not yet contain a just-created Job — fewer
// Jobs than target nodes must never read as Completed.
func TestComputeSessionState_UndercountedJobsNotTerminal(t *testing.T) {
	succeeded := batchv1.Job{Status: batchv1.JobStatus{Succeeded: 1}}
	state := computeSessionState([]batchv1.Job{succeeded}, 2)
	if state == podtracev1alpha1.SessionStateCompleted || state == podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %s with 1 of 2 expected Jobs visible, must not be terminal", state)
	}
	if state := computeSessionState([]batchv1.Job{succeeded}, 1); state != podtracev1alpha1.SessionStateCompleted {
		t.Errorf("state = %s with all expected Jobs succeeded, want Completed", state)
	}
}

// TestComputeSessionState_DeadlineExceededIsTerminal regression: a
// Job killed by ActiveDeadlineSeconds carries a JobFailed condition (reason
// DeadlineExceeded) but its .status.Failed count does not exceed backoffLimit.
func TestComputeSessionState_DeadlineExceededIsTerminal(t *testing.T) {
	backoff := int32(6)
	deadlineKilled := batchv1.Job{
		Spec: batchv1.JobSpec{BackoffLimit: &backoff},
		Status: batchv1.JobStatus{
			Failed: 1,
			Conditions: []batchv1.JobCondition{{
				Type:   batchv1.JobFailed,
				Status: corev1.ConditionTrue,
				Reason: "DeadlineExceeded",
			}},
		},
	}
	if state := computeSessionState([]batchv1.Job{deadlineKilled}, 1); state != podtracev1alpha1.SessionStateFailed {
		t.Errorf("deadline-exceeded Job: state = %s, want Failed (else the session re-runs forever)", state)
	}

	complete := batchv1.Job{Status: batchv1.JobStatus{
		Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}},
	}}
	if state := computeSessionState([]batchv1.Job{complete}, 1); state != podtracev1alpha1.SessionStateCompleted {
		t.Errorf("JobComplete condition: state = %s, want Completed", state)
	}
}

// TestSessionValidationFailureIsTerminalAndGCable: validation failures used
// to set Failed without a CompletionTime (never TTL-collected) and returned
// an error on a permanently failed object (infinite backoff).
func TestSessionValidationFailureIsTerminalAndGCable(t *testing.T) {
	scheme := newOperatorScheme(t)
	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bad-store", Namespace: "default", UID: "s-1",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Duration:    metav1.Duration{Duration: 30 * time.Second},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
			ReportRef: &podtracev1alpha1.ReportReference{
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "ftp://not-supported/x"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "bad-store"},
	})
	if err != nil {
		t.Fatalf("terminally failed session must not return an error (infinite backoff), got %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want none for a terminal validation failure", res.RequeueAfter)
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "bad-store"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %s, want Failed", got.Status.State)
	}
	if got.Status.CompletionTime == nil {
		t.Error("CompletionTime must be stamped so the TTL garbage collector can reap the session")
	}
}

// TestNonDefaultTracerConfigIsInert: the agent DaemonSet has one fixed name,
// so a second TracerConfig used to fight the first over owner references and
// the immutable selector, failing its reconcile forever.
func TestNonDefaultTracerConfigIsInert(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "secondary"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "secondary"},
	}); err != nil {
		t.Fatalf("non-default TracerConfig must reconcile without error, got %v", err)
	}

	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: "secondary"}, &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cond := range got.Status.Conditions {
		if cond.Type == ConditionDegraded && cond.Reason == "NotDefaultTracerConfig" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Degraded/NotDefaultTracerConfig condition, got %+v", got.Status.Conditions)
	}
}

// TestScheduleSkipsBacklogPastMissedRunBound: without startingDeadlineSeconds
// every missed tick used to replay serially — a month-long suspension at a
// minutely cron meant tens of thousands of stale sessions.
func TestScheduleSkipsBacklogPastMissedRunBound(t *testing.T) {
	scheme := newOperatorScheme(t)
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "backlogged", Namespace: "default", UID: "sch-backlog",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-24 * time.Hour)),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *", // 288 missed ticks in 24h
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{
					Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
					Duration:    metav1.Duration{Duration: 30 * time.Second},
					ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
				},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(sch).Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: scheme, nowFn: func() time.Time { return fixedScheduleNow }}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "backlogged"},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var sessions podtracev1alpha1.PodTraceSessionList
	if err := c.List(context.Background(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 0 {
		t.Errorf("backlog must be skipped, got %d sessions fired", len(sessions.Items))
	}
	var got podtracev1alpha1.PodTraceSchedule
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "backlogged"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.LastScheduleTime == nil || !got.Status.LastScheduleTime.Time.Equal(fixedScheduleNow) {
		t.Errorf("LastScheduleTime = %v, want jumped to now (%v)", got.Status.LastScheduleTime, fixedScheduleNow)
	}
}

// TestApplicationTraceRefusesAdoption: a pre-existing user PodTrace with the
// same name used to be silently adopted — its spec overwritten and an
// ownerReference added that garbage-collects it with the ApplicationTrace.
func TestApplicationTraceRefusesAdoption(t *testing.T) {
	scheme := newOperatorScheme(t)
	app := mkApp()
	userPT := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: app.Name, Namespace: app.Namespace},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "user-owned"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "user-ec"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app, userPT).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: app.Namespace, Name: app.Name},
	})
	if err == nil {
		t.Fatal("expected an error refusing to adopt the user-owned PodTrace")
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: app.Namespace, Name: app.Name}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ExporterRef.Name != "user-ec" {
		t.Errorf("user PodTrace spec was overwritten: exporterRef = %q", got.Spec.ExporterRef.Name)
	}
	if len(got.OwnerReferences) != 0 {
		t.Errorf("user PodTrace gained owner references: %+v", got.OwnerReferences)
	}
}
