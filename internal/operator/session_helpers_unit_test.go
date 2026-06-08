package operator

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestSess_TerminalCompletedNoCompletionTimeIsNoOp(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	session.Status.State = podtracev1alpha1.SessionStateCompleted

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	})
	if err != nil {
		t.Fatalf("terminal session no-op must not error, got %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("terminal session with nil CompletionTime must not requeue, got %+v", res)
	}
}

func TestSess_TerminalFailedWithinTTLRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	session.Status.State = podtracev1alpha1.SessionStateFailed
	now := metav1.Now()
	session.Status.CompletionTime = &now

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	})
	if err != nil {
		t.Fatalf("terminal session within TTL must not error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("terminal session within TTL must requeue, got %+v", res)
	}
}

func TestSess_NodeAtCapacityRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{MaxConcurrentSessionsPerNode: 1},
	}
	otherJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-session-job",
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: "other-session",
				LabelSessionNS:   "team-b",
				LabelNodeName:    "n1",
			},
		},
		Status: batchv1.JobStatus{Active: 1},
	}

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session, pod, ec, tc, otherJob).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	})
	if err != nil {
		t.Fatalf("node-at-capacity must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when node at capacity, got %+v", res)
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &got); err != nil {
		t.Fatalf("re-get session: %v", err)
	}
	if !hasDegradedReason(got.Status.Conditions, "NodeCapacity") {
		t.Fatalf("expected NodeCapacity degraded condition, got %+v", got.Status.Conditions)
	}
}

func TestSess_EnsureJobsCreateError(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session, pod, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*batchv1.Job); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	}); err == nil {
		t.Fatal("expected ensureJobs create error from session Reconcile")
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &got); err != nil {
		t.Fatalf("re-get session: %v", err)
	}
	if !hasDegradedReason(got.Status.Conditions, "EnsureJobs") {
		t.Fatalf("expected EnsureJobs degraded condition, got %+v", got.Status.Conditions)
	}
}

func TestSess_PopulateSummariesListError(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")
	now := metav1.Now()
	ownedJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionJobName(session.UID, "n1"),
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: session.Name,
				LabelSessionNS:   session.Namespace,
				LabelNodeName:    "n1",
			},
		},
		Status: batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
	}

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session, pod, ec, ownedJob).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	}); err == nil {
		t.Fatal("expected populateSessionSummaries pod-list error from session Reconcile")
	}
}

func hasDegradedReason(conds []metav1.Condition, reason string) bool {
	for _, c := range conds {
		if c.Type == ConditionDegraded && c.Status == metav1.ConditionTrue && c.Reason == reason {
			return true
		}
	}
	return false
}

func TestSess_MakeSessionJobRefsEmpty(t *testing.T) {
	refs := makeSessionJobRefs(nil)
	if len(refs) != 0 {
		t.Fatalf("expected zero refs for empty input, got %d", len(refs))
	}
}

func TestSess_MakeSessionJobRefsPopulated(t *testing.T) {
	start := metav1.NewTime(time.Date(2026, 6, 8, 11, 0, 0, 0, time.UTC))
	complete := metav1.NewTime(time.Date(2026, 6, 8, 11, 5, 0, 0, time.UTC))
	backoff := int32(0)

	running := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "job-running",
			Labels: map[string]string{LabelNodeName: "n1"},
		},
		Spec:   batchv1.JobSpec{BackoffLimit: &backoff},
		Status: batchv1.JobStatus{Active: 1, StartTime: &start},
	}
	failed := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "job-failed",
			Labels: map[string]string{LabelNodeName: "n2"},
		},
		Spec:   batchv1.JobSpec{BackoffLimit: &backoff},
		Status: batchv1.JobStatus{Failed: 1, StartTime: &start, CompletionTime: &complete},
	}

	refs := makeSessionJobRefs([]batchv1.Job{running, failed})
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}

	if refs[0].Node != "n1" || refs[0].Name != "job-running" {
		t.Fatalf("unexpected running ref: %+v", refs[0])
	}
	if refs[0].Completed {
		t.Fatalf("running Job must not be marked completed: %+v", refs[0])
	}
	if refs[0].StartTime == nil || refs[0].CompletionTime != nil {
		t.Fatalf("running Job ref should carry StartTime and no CompletionTime: %+v", refs[0])
	}
	if refs[0].Message != "" {
		t.Fatalf("running Job must not carry a failure message: %+v", refs[0])
	}

	if !refs[1].Completed {
		t.Fatalf("failed Job past backoff limit must be marked completed: %+v", refs[1])
	}
	if refs[1].CompletionTime == nil || refs[1].StartTime == nil {
		t.Fatalf("failed Job ref should carry both timestamps: %+v", refs[1])
	}
	if refs[1].Message != "Job failed" {
		t.Fatalf("failed Job ref should carry the failure message, got %q", refs[1].Message)
	}
}

func finishedJob(name, ns, node string) *batchv1.Job {
	now := metav1.Now()
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{LabelNodeName: node},
		},
		Status: batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
	}
}

func podForJob(jobName, ns string, terminated *corev1.ContainerStateTerminated) *corev1.Pod {
	cs := corev1.ContainerStatus{Name: "podtrace"}
	if terminated != nil {
		cs.State = corev1.ContainerState{Terminated: terminated}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName + "-abc",
			Namespace: ns,
			Labels:    map[string]string{"job-name": jobName},
		},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{cs}},
	}
}

func TestSess_ReadTerminationSummaryParsesMessage(t *testing.T) {
	s := newOperatorScheme(t)
	job := finishedJob("job-1", "podtrace-system", "n1")
	pod := podForJob("job-1", "podtrace-system", &corev1.ContainerStateTerminated{
		Message: `{"totalEvents":42,"netEvents":7,"node":"n1"}`,
	})

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod).Build()

	summary, err := readTerminationSummaryForJob(context.Background(), c, job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary == nil {
		t.Fatal("expected a decoded summary, got nil")
	}
	if summary.TotalEvents != 42 || summary.NetEvents != 7 || summary.Node != "n1" {
		t.Fatalf("summary not parsed correctly: %+v", summary)
	}
}

func TestSess_ReadTerminationSummaryUnfinishedJob(t *testing.T) {
	s := newOperatorScheme(t)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "job-pending", Namespace: "podtrace-system"},
	}
	c := fake.NewClientBuilder().WithScheme(s).Build()

	summary, err := readTerminationSummaryForJob(context.Background(), c, job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary != nil {
		t.Fatalf("unfinished Job must yield nil summary, got %+v", summary)
	}
}

func TestSess_ReadTerminationSummaryEmptyMessage(t *testing.T) {
	s := newOperatorScheme(t)
	job := finishedJob("job-empty", "podtrace-system", "n1")
	pod := podForJob("job-empty", "podtrace-system", &corev1.ContainerStateTerminated{Message: ""})

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod).Build()

	summary, err := readTerminationSummaryForJob(context.Background(), c, job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary != nil {
		t.Fatalf("empty termination message must yield nil summary, got %+v", summary)
	}
}

func TestSess_ReadTerminationSummaryMalformedMessage(t *testing.T) {
	s := newOperatorScheme(t)
	job := finishedJob("job-bad", "podtrace-system", "n1")
	pod := podForJob("job-bad", "podtrace-system", &corev1.ContainerStateTerminated{Message: "{not-json"})

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod).Build()

	summary, err := readTerminationSummaryForJob(context.Background(), c, job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary != nil {
		t.Fatalf("malformed termination message must yield nil summary, got %+v", summary)
	}
}

func TestSess_ReadTerminationSummaryNoTerminatedContainer(t *testing.T) {
	s := newOperatorScheme(t)
	job := finishedJob("job-running-pod", "podtrace-system", "n1")
	pod := podForJob("job-running-pod", "podtrace-system", nil)

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod).Build()

	summary, err := readTerminationSummaryForJob(context.Background(), c, job)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary != nil {
		t.Fatalf("non-terminated container must yield nil summary, got %+v", summary)
	}
}

func TestSess_ReadTerminationSummaryListError(t *testing.T) {
	s := newOperatorScheme(t)
	job := finishedJob("job-list-err", "podtrace-system", "n1")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return errInternal()
				}
				return nil
			},
		}).
		Build()

	if _, err := readTerminationSummaryForJob(context.Background(), c, job); err == nil {
		t.Fatal("expected pod-list error to surface")
	}
}

func gcSession(name string, state podtracev1alpha1.SessionState, completedAt time.Time) podtracev1alpha1.PodTraceSession {
	ct := metav1.NewTime(completedAt)
	return podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			State:          state,
			CompletionTime: &ct,
		},
	}
}

func TestSess_ApplyHistoryLimitsSuccessfulDeleteError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}

	limit := int32(1)
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "sch", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			SuccessfulSessionsHistoryLimit: &limit,
		},
	}
	succeeded := []podtracev1alpha1.PodTraceSession{
		gcSession("succ-old", podtracev1alpha1.SessionStateCompleted, fixedScheduleNow.Add(-2*time.Hour)),
		gcSession("succ-new", podtracev1alpha1.SessionStateCompleted, fixedScheduleNow.Add(-1*time.Hour)),
	}

	err := r.applyHistoryLimits(context.Background(), sch, succeeded, nil)
	if err == nil {
		t.Fatal("expected applyHistoryLimits to surface successful-history gc error")
	}
	if got := err.Error(); !contains(got, "gc successful") {
		t.Fatalf("expected wrapped 'gc successful' error, got %q", got)
	}
}

func TestSess_ApplyHistoryLimitsFailedDeleteError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}

	limit := int32(1)
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "sch", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			FailedSessionsHistoryLimit: &limit,
		},
	}
	failed := []podtracev1alpha1.PodTraceSession{
		gcSession("fail-old", podtracev1alpha1.SessionStateFailed, fixedScheduleNow.Add(-2*time.Hour)),
		gcSession("fail-new", podtracev1alpha1.SessionStateFailed, fixedScheduleNow.Add(-1*time.Hour)),
	}

	err := r.applyHistoryLimits(context.Background(), sch, nil, failed)
	if err == nil {
		t.Fatal("expected applyHistoryLimits to surface failed-history gc error")
	}
	if got := err.Error(); !contains(got, "gc failed") {
		t.Fatalf("expected wrapped 'gc failed' error, got %q", got)
	}
}

func TestSess_NewSchemeRegistersTypes(t *testing.T) {
	sc, err := NewScheme()
	if err != nil {
		t.Fatalf("NewScheme returned error: %v", err)
	}
	if sc == nil {
		t.Fatal("NewScheme returned nil scheme")
	}
	if !sc.Recognizes(podtracev1alpha1.GroupVersion.WithKind("PodTraceSession")) {
		t.Fatal("scheme does not recognize PodTraceSession")
	}
	if !sc.Recognizes(corev1.SchemeGroupVersion.WithKind("Pod")) {
		t.Fatal("scheme does not recognize core Pod")
	}
}
