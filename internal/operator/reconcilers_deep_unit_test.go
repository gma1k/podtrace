package operator

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// ─── PodTraceSessionReconciler.Reconcile — deeper branches ───────────

// TestDeepReconcile_Session_BadObjectStoreURI drives the early
// ValidateObjectStoreReference branch: an invalid objectStore URI marks
// the session Failed via Degraded and returns no error.
func TestDeepReconcile_Session_BadObjectStoreURI(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: ns, UID: "uid-s",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
			ReportRef: &podtracev1alpha1.ReportReference{
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "ftp://nope"},
			},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %q, want Failed", got.Status.State)
	}
	if !hasCondition(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
		t.Errorf("expected Degraded=True, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Session_ExporterNotFound drives the path where pods
// match (target nodes resolved) but the referenced ExporterConfig is
// missing: Degraded=True/ExporterNotFound, requeue, no error.
func TestDeepReconcile_Session_ExporterNotFound(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: "n1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: ns, UID: "uid-s",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "missing-ec"},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s, pod).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected positive RequeueAfter when exporter missing")
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
		t.Errorf("expected Degraded=True, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Session_FullFanOut drives the full happy path: pods
// matched, ExporterConfig present, bundle/SA/RBAC ensured, Jobs created,
// status rolled up. This is the deepest branch of Reconcile.
func TestDeepReconcile_Session_FullFanOut(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	pods := []client.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, Labels: map[string]string{"a": "b"}},
			Spec:       corev1.PodSpec{NodeName: "n1"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, Labels: map[string]string{"a": "b"}},
			Spec:       corev1.PodSpec{NodeName: "n2"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: ns, UID: "uid-s", Generation: 3,
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
	scheme := newOperatorScheme(t)
	objs := append(pods, s, ec)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected positive RequeueAfter for non-terminal session")
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ObservedGeneration != s.Generation {
		t.Errorf("ObservedGeneration = %d, want %d", got.Status.ObservedGeneration, s.Generation)
	}
	if !hasCondition(got.Status.Conditions, ConditionReconciled, metav1.ConditionTrue) {
		t.Errorf("expected Reconciled=True, got %+v", got.Status.Conditions)
	}
	if len(got.Status.Jobs) != 2 {
		t.Errorf("expected 2 Job refs, got %d", len(got.Status.Jobs))
	}
	bundleName := SessionBundleName(s.UID)
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &corev1.ConfigMap{}); err != nil {
		t.Errorf("session bundle ConfigMap missing: %v", err)
	}
}

// TestDeepReconcile_Session_DeletionRunsCleanup drives the deletion path:
// a session with a deletion timestamp cleans up children and clears the
// finalizer.
func TestDeepReconcile_Session_DeletionRunsCleanup(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	now := metav1.Now()
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: ns, UID: "uid-s",
			Finalizers:        []string{FinalizerCleanup},
			DeletionTimestamp: &now,
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &podtracev1alpha1.PodTraceSession{})
	if err == nil {
		var leftover podtracev1alpha1.PodTraceSession
		_ = c.Get(context.Background(), client.ObjectKeyFromObject(s), &leftover)
		if len(leftover.Finalizers) != 0 {
			t.Errorf("finalizer should have been removed, got %v", leftover.Finalizers)
		}
	}
}

// TestDeepReconcile_ResolveTargetNodes_NamespaceSelector drives the
// cluster-wide list + allowlist filter branch of resolveSessionTargets
// (the existing test only covers the own-namespace + podRefs branches),
// including the tenancy grant.
func TestDeepReconcile_ResolveTargetNodes_NamespaceSelector(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:        "allowed",
			Labels:      map[string]string{"team": "obs"},
			Annotations: map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: "default"},
		}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   "ungranted",
			Labels: map[string]string{"team": "obs"},
		}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "denied"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p-allowed", Namespace: "allowed", Labels: map[string]string{"app": "x"}},
			Spec:       corev1.PodSpec{NodeName: "n-allowed"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p-ungranted", Namespace: "ungranted", Labels: map[string]string{"app": "x"}},
			Spec:       corev1.PodSpec{NodeName: "n-ungranted"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p-denied", Namespace: "denied", Labels: map[string]string{"app": "x"}},
			Spec:       corev1.PodSpec{NodeName: "n-denied"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "obs"}},
		},
	}
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	targets, err := r.resolveSessionTargets(context.Background(), s)
	if err != nil {
		t.Fatalf("resolveSessionTargets: %v", err)
	}
	if len(targets.Nodes) != 1 || targets.Nodes[0] != "n-allowed" {
		t.Errorf("nodes = %v, want [n-allowed]", targets.Nodes)
	}
	if len(targets.Namespaces) != 1 || targets.Namespaces[0] != "allowed" {
		t.Errorf("namespaces = %v, want [allowed]", targets.Namespaces)
	}
	if len(targets.DeniedNamespaces) != 1 || targets.DeniedNamespaces[0] != "ungranted" {
		t.Errorf("deniedNamespaces = %v, want [ungranted]", targets.DeniedNamespaces)
	}
}

// TestDeepReconcile_ResolveTargetNodes_EmptyAllowlist drives the
// "selector set but no namespaces match" short-circuit.
func TestDeepReconcile_ResolveTargetNodes_EmptyAllowlist(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "x", Labels: map[string]string{"app": "x"}},
			Spec:       corev1.PodSpec{NodeName: "n1"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	).Build()
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "nomatch"}},
		},
	}
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	targets, err := r.resolveSessionTargets(context.Background(), s)
	if err != nil {
		t.Fatalf("resolveSessionTargets: %v", err)
	}
	if len(targets.Nodes) != 0 {
		t.Errorf("nodes = %v, want empty (no namespaces match)", targets.Nodes)
	}
	if targets.Namespaces == nil || len(targets.Namespaces) != 0 {
		t.Errorf("namespaces = %v, want empty non-nil slice", targets.Namespaces)
	}
}

// ─── PodTraceScheduleReconciler.Reconcile — deeper branches ──────────

func newScheduleSpec(schedule string) podtracev1alpha1.PodTraceScheduleSpec {
	return podtracev1alpha1.PodTraceScheduleSpec{
		Schedule: schedule,
		SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
			Spec: podtracev1alpha1.PodTraceSessionSpec{},
		},
	}
}

// TestDeepReconcile_Schedule_Suspended drives the suspend short-circuit:
// no session is created, Paused=True is recorded, and history GC still runs.
func TestDeepReconcile_Schedule_Suspended(t *testing.T) {
	suspend := true
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "suspended", Namespace: "default", UID: "sus-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-time.Hour)),
		},
		Spec: newScheduleSpec("*/5 * * * *"),
	}
	sch.Spec.Suspend = &suspend

	r, _ := newScheduleReconciler(t, sch)
	ctx := context.Background()
	res, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != scheduleResyncCeiling {
		t.Errorf("RequeueAfter = %v, want %v", res.RequeueAfter, scheduleResyncCeiling)
	}

	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions, client.InNamespace(sch.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 0 {
		t.Errorf("suspended schedule should create no sessions, got %d", len(sessions.Items))
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, client.ObjectKeyFromObject(sch), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionPaused, metav1.ConditionTrue) {
		t.Errorf("expected Paused=True, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Schedule_BadTimezone drives the parseSchedule error
// branch through Reconcile: Degraded=True/ScheduleInvalid, no requeue, nil err.
func TestDeepReconcile_Schedule_BadTimezone(t *testing.T) {
	bad := "Not/AZone"
	spec := newScheduleSpec("*/5 * * * *")
	spec.TimeZone = &bad
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "badtz", Namespace: "default", UID: "tz-uid"},
		Spec:       spec,
	}

	r, _ := newScheduleReconciler(t, sch)
	ctx := context.Background()
	res, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0 (invalid schedule is not re-queued)", res.RequeueAfter)
	}
	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, client.ObjectKeyFromObject(sch), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
		t.Errorf("expected Degraded=True, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Schedule_FutureNextRunNoTrigger drives the
// now.Before(nextRun) branch: a schedule that just ran (LastScheduleTime
// set to now) is not due again, so no new session is created.
func TestDeepReconcile_Schedule_FutureNextRunNoTrigger(t *testing.T) {
	last := metav1.NewTime(fixedScheduleNow)
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "future", Namespace: "default", UID: "fut-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-time.Hour)),
		},
		Spec: newScheduleSpec("*/5 * * * *"),
		Status: podtracev1alpha1.PodTraceScheduleStatus{
			LastScheduleTime: &last,
		},
	}

	r, _ := newScheduleReconciler(t, sch)
	ctx := context.Background()
	res, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected positive RequeueAfter for not-yet-due schedule, got %v", res.RequeueAfter)
	}

	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions, client.InNamespace(sch.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 0 {
		t.Errorf("not-due schedule should create no sessions, got %d", len(sessions.Items))
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, client.ObjectKeyFromObject(sch), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionReconciled, metav1.ConditionTrue) {
		t.Errorf("expected Reconciled=True, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Schedule_ForbidConcurrent drives the Forbid policy
// branch: an active child session blocks a new run from being triggered.
func TestDeepReconcile_Schedule_ForbidConcurrent(t *testing.T) {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "forbid", Namespace: "default", UID: "forbid-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-time.Hour)),
		},
		Spec: newScheduleSpec("*/5 * * * *"),
	}
	sch.Spec.ConcurrencyPolicy = podtracev1alpha1.ForbidConcurrent

	active := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "active-child", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: podtracev1alpha1.GroupVersion.String(),
				Kind:       "PodTraceSchedule",
				Name:       sch.Name,
				UID:        sch.UID,
			}},
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateRunning},
	}

	r, _ := newScheduleReconciler(t, sch, active)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions, client.InNamespace(sch.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 1 {
		t.Errorf("Forbid should not create a new session while one is active, got %d", len(sessions.Items))
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, client.ObjectKeyFromObject(sch), &got); err != nil {
		t.Fatal(err)
	}
	if !conditionHasReason(got.Status.Conditions, ConditionReconciled, "Forbidden") {
		t.Errorf("expected Reconciled reason Forbidden, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Schedule_MaxActiveSessions drives the
// MaxActiveSessions safety-valve branch.
func TestDeepReconcile_Schedule_MaxActiveSessions(t *testing.T) {
	cap := int32(1)
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "maxactive", Namespace: "default", UID: "max-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-time.Hour)),
		},
		Spec: newScheduleSpec("*/5 * * * *"),
	}
	sch.Spec.MaxActiveSessions = &cap

	active := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "active-child", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: podtracev1alpha1.GroupVersion.String(),
				Kind:       "PodTraceSchedule",
				Name:       sch.Name,
				UID:        sch.UID,
			}},
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateRunning},
	}

	r, _ := newScheduleReconciler(t, sch, active)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, client.ObjectKeyFromObject(sch), &got); err != nil {
		t.Fatal(err)
	}
	if !conditionHasReason(got.Status.Conditions, ConditionReconciled, "ActiveLimitReached") {
		t.Errorf("expected Reconciled reason ActiveLimitReached, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Schedule_ReplaceConcurrent drives the Replace policy
// branch: active sessions are deleted before a new run is triggered.
func TestDeepReconcile_Schedule_ReplaceConcurrent(t *testing.T) {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "replace", Namespace: "default", UID: "replace-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-time.Hour)),
		},
		Spec: newScheduleSpec("*/5 * * * *"),
	}
	sch.Spec.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent

	active := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "stale-child", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: podtracev1alpha1.GroupVersion.String(),
				Kind:       "PodTraceSchedule",
				Name:       sch.Name,
				UID:        sch.UID,
			}},
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateRunning},
	}

	r, _ := newScheduleReconciler(t, sch, active)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if err := r.Get(ctx, client.ObjectKeyFromObject(active), &podtracev1alpha1.PodTraceSession{}); err == nil {
		t.Error("Replace should have deleted the stale active session")
	}
	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, client.ObjectKeyFromObject(sch), &got); err != nil {
		t.Fatal(err)
	}
	if !conditionHasReason(got.Status.Conditions, ConditionReconciled, "Triggered") {
		t.Errorf("expected Reconciled reason Triggered, got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_Schedule_MissedDeadline drives the
// StartingDeadlineSeconds missed-run branch. CreationTimestamp far in the
// past makes nextRun stale and now past the deadline window.
func TestDeepReconcile_Schedule_MissedDeadline(t *testing.T) {
	deadline := int64(1) // 1s window; nextRun is hours stale.
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "missed", Namespace: "default", UID: "missed-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-24 * time.Hour)),
		},
		Spec: newScheduleSpec("*/5 * * * *"),
	}
	sch.Spec.StartingDeadlineSeconds = &deadline

	r, _ := newScheduleReconciler(t, sch)
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, client.ObjectKeyFromObject(sch), &got); err != nil {
		t.Fatal(err)
	}
	if !conditionHasReason(got.Status.Conditions, ConditionReconciled, "MissedDeadline") {
		t.Errorf("expected Reconciled reason MissedDeadline, got %+v", got.Status.Conditions)
	}
	if got.Status.LastScheduleTime == nil {
		t.Error("expected LastScheduleTime to be advanced past the missed run")
	}
}

// ─── TracerConfigReconciler.Reconcile — deeper branches ──────────────

// TestDeepReconcile_TracerConfig_CustomNamespace drives Reconcile with a
// spec.systemNamespace override, asserting the DaemonSet lands there and
// status is rolled up (ReadyAgents/DesiredAgents both 0 → Ready=False).
func TestDeepReconcile_TracerConfig_CustomNamespace(t *testing.T) {
	const customNS = "custom-sys"
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", UID: "tc-uid", Generation: 4},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: customNS},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).Build()

	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "fallback-sys"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: tc.Name},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var ds appsv1.DaemonSet
	if err := c.Get(context.Background(), types.NamespacedName{Name: AgentDaemonSetName(), Namespace: customNS}, &ds); err != nil {
		t.Errorf("DaemonSet not created in custom namespace %s: %v", customNS, err)
	}

	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: tc.Name}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ObservedGeneration != tc.Generation {
		t.Errorf("ObservedGeneration = %d, want %d", got.Status.ObservedGeneration, tc.Generation)
	}
	if !hasCondition(got.Status.Conditions, ConditionReconciled, metav1.ConditionTrue) {
		t.Errorf("expected Reconciled=True, got %+v", got.Status.Conditions)
	}
	if !hasCondition(got.Status.Conditions, ConditionReady, metav1.ConditionFalse) {
		t.Errorf("expected Ready=False (0 desired agents), got %+v", got.Status.Conditions)
	}
}

// ─── ApplicationTraceReconciler.Reconcile — deeper branches ──────────

// TestDeepReconcile_ApplicationTrace_HappyPath drives Reconcile end-to-end:
// child PodTrace created with translated appSelector, status aggregated,
// Reconciled/Ready conditions set, patchStatus persists.
func TestDeepReconcile_ApplicationTrace_HappyPath(t *testing.T) {
	const ns = "default"
	app := &podtracev1alpha1.ApplicationTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "app1", Namespace: ns, UID: "app-uid", Generation: 2},
		Spec: podtracev1alpha1.ApplicationTraceSpec{
			Selectors:   []metav1.LabelSelector{{MatchLabels: map[string]string{"app": "x"}}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app).Build()

	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: app.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var pt podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: app.Name, Namespace: ns}, &pt); err != nil {
		t.Fatalf("child PodTrace not created: %v", err)
	}
	if pt.Spec.AppSelector == nil || len(pt.Spec.AppSelector.MatchSelectors) != 1 {
		t.Errorf("appSelector not translated: %+v", pt.Spec.AppSelector)
	}
	if pt.Labels[LabelApplication] != app.Name {
		t.Errorf("application label = %q, want %q", pt.Labels[LabelApplication], app.Name)
	}

	var got podtracev1alpha1.ApplicationTrace
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(app), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.PodTraceRef != app.Name {
		t.Errorf("PodTraceRef = %q, want %q", got.Status.PodTraceRef, app.Name)
	}
	if got.Status.ObservedGeneration != app.Generation {
		t.Errorf("ObservedGeneration = %d, want %d", got.Status.ObservedGeneration, app.Generation)
	}
	if !hasCondition(got.Status.Conditions, ConditionReconciled, metav1.ConditionTrue) {
		t.Errorf("expected Reconciled=True, got %+v", got.Status.Conditions)
	}
	if !hasCondition(got.Status.Conditions, ConditionReady, metav1.ConditionFalse) {
		t.Errorf("expected Ready=False (child not ready), got %+v", got.Status.Conditions)
	}
}

// TestDeepReconcile_ApplicationTrace_Paused drives the spec.paused branch
// (Paused=True condition) while still ensuring the child PodTrace.
func TestDeepReconcile_ApplicationTrace_Paused(t *testing.T) {
	const ns = "default"
	app := &podtracev1alpha1.ApplicationTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "app-paused", Namespace: ns, UID: "appp-uid"},
		Spec: podtracev1alpha1.ApplicationTraceSpec{
			Selectors:   []metav1.LabelSelector{{MatchLabels: map[string]string{"app": "x"}}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
			Paused:      true,
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app).Build()

	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: app.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.ApplicationTrace
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(app), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionPaused, metav1.ConditionTrue) {
		t.Errorf("expected Paused=True, got %+v", got.Status.Conditions)
	}
	var pt podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: app.Name, Namespace: ns}, &pt); err != nil {
		t.Fatal(err)
	}
	if !pt.Spec.Paused {
		t.Error("child PodTrace should inherit spec.paused")
	}
}

// ─── PodTraceReconciler.Reconcile — DataDog bundle (syncExporterBundle) ──

// TestDeepReconcile_PodTrace_DataDogBundleWithSecret drives the
// syncExporterBundle credential-Secret branch: a DataDog exporter whose
// API key lives in a user-namespace Secret produces both the bundle
// ConfigMap and the paired Secret in the system namespace.
func TestDeepReconcile_PodTrace_DataDogBundleWithSecret(t *testing.T) {
	const sysNS, ns = "podtrace-system", "default"
	pct := int32(50)
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: ns, UID: "uid-dd",
			Finalizers: []string{FinalizerCleanup},
			Generation: 5,
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:      &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef:   podtracev1alpha1.LocalObjectReference{Name: "dd"},
			SamplePercent: &pct,
			Filters:       []podtracev1alpha1.EventFilter{"network", "filesystem"},
		},
	}
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				Site:            "datadoghq.eu",
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd-creds", Key: "api-key"},
			},
		},
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dd-creds", Namespace: ns},
		Data:       map[string][]byte{"api-key": []byte("secret-key")},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec, sec).Build()

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	bundleName := ExporterBundleName(pt.UID)
	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &cm); err != nil {
		t.Fatalf("bundle ConfigMap missing: %v", err)
	}
	if cm.Data["type"] != "datadog" || cm.Data["site"] != "datadoghq.eu" {
		t.Errorf("bundle data wrong: %+v", cm.Data)
	}
	if cm.Data["header_secret_name"] != "DD-API-KEY" {
		t.Errorf("expected header_secret_name DD-API-KEY, got %q", cm.Data["header_secret_name"])
	}
	var bundleSec corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &bundleSec); err != nil {
		t.Fatalf("bundle Secret missing: %v", err)
	}
	if string(bundleSec.Data["credential"]) != "secret-key" {
		t.Errorf("credential = %q, want secret-key", bundleSec.Data["credential"])
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pt), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionPolicyApplied, metav1.ConditionTrue) {
		t.Errorf("expected PolicyApplied=True, got %+v", got.Status.Conditions)
	}
	if got.Status.Policy == nil {
		t.Error("expected status.Policy to be resolved")
	}
}

// TestDeepReconcile_PodTrace_BundleSyncError drives the syncExporterBundle
// failure branch: a DataDog exporter whose credential Secret is missing
// sets Degraded/PolicyApplied=False and requeues without error.
func TestDeepReconcile_PodTrace_BundleSyncError(t *testing.T) {
	const sysNS, ns = "podtrace-system", "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: ns, UID: "uid-err",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "dd"},
		},
	}
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "absent-creds", Key: "api-key"},
			},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec).Build()

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected positive RequeueAfter on bundle sync error")
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pt), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
		t.Errorf("expected Degraded=True, got %+v", got.Status.Conditions)
	}
	if !hasCondition(got.Status.Conditions, ConditionPolicyApplied, metav1.ConditionFalse) {
		t.Errorf("expected PolicyApplied=False, got %+v", got.Status.Conditions)
	}
}

// ─── ensureSessionObjectStoreCredentials ─────────────────────────────

// TestDeepReconcile_SessionObjectStoreCreds covers all branches of the
// standalone helper: no-op (no ReportRef), no-op (no secret ref), missing
// source Secret error, and the happy-path copy into the system namespace.
func TestDeepReconcile_SessionObjectStoreCreds(t *testing.T) {
	const sysNS, ns = "ns-sys", "team-a"
	scheme := newOperatorScheme(t)

	if name, err := ensureSessionObjectStoreCredentials(context.Background(),
		fake.NewClientBuilder().WithScheme(scheme).Build(),
		&podtracev1alpha1.PodTraceSession{}, sysNS); err != nil || name != "" {
		t.Errorf("nil ReportRef: name=%q err=%v, want empty/nil", name, err)
	}

	sNoCreds := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: ns, UID: "uid-nc"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://b/k"},
			},
		},
	}
	if name, err := ensureSessionObjectStoreCredentials(context.Background(),
		fake.NewClientBuilder().WithScheme(scheme).Build(), sNoCreds, sysNS); err != nil || name != "" {
		t.Errorf("no creds ref: name=%q err=%v, want empty/nil", name, err)
	}

	sMissing := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: ns, UID: "uid-miss"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{
					URI:                  "s3://b/k",
					CredentialsSecretRef: &corev1.LocalObjectReference{Name: "absent"},
				},
			},
		},
	}
	if _, err := ensureSessionObjectStoreCredentials(context.Background(),
		fake.NewClientBuilder().WithScheme(scheme).Build(), sMissing, sysNS); err == nil {
		t.Error("expected error when source Secret is missing")
	}

	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "obj-creds", Namespace: ns},
		Data:       map[string][]byte{"access_key_id": []byte("AKIA"), "secret_access_key": []byte("shh")},
	}
	sOK := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: ns, UID: "uid-ok"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{
					URI:                  "s3://b/k",
					CredentialsSecretRef: &corev1.LocalObjectReference{Name: "obj-creds"},
				},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(src).Build()
	dstName, err := ensureSessionObjectStoreCredentials(context.Background(), c, sOK, sysNS)
	if err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if dstName != SessionObjectStoreCredsName(sOK.UID) {
		t.Errorf("dstName = %q, want %q", dstName, SessionObjectStoreCredsName(sOK.UID))
	}
	var dst corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: dstName, Namespace: sysNS}, &dst); err != nil {
		t.Fatalf("copied Secret missing: %v", err)
	}
	if string(dst.Data["access_key_id"]) != "AKIA" || string(dst.Data["secret_access_key"]) != "shh" {
		t.Errorf("copied Secret data wrong: %+v", dst.Data)
	}
	if dst.Labels[LabelSessionName] != sOK.Name {
		t.Errorf("session label not set on copy: %+v", dst.Labels)
	}
}

// ─── exporter_bundle.go policy lifters ───────────────────────────────

// TestDeepReconcile_PolicyLifters covers the nil branch of
// policyFromPodTrace / policyFromSession (the populated branch is already
// exercised elsewhere).
func TestDeepReconcile_PolicyLifters(t *testing.T) {
	if policyFromPodTrace(nil) != nil {
		t.Error("policyFromPodTrace(nil) should be nil")
	}
	if policyFromSession(nil) != nil {
		t.Error("policyFromSession(nil) should be nil")
	}

	pct := int32(25)
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Generation: 9},
		Spec: podtracev1alpha1.PodTraceSpec{
			Filters:       []podtracev1alpha1.EventFilter{"network"},
			SamplePercent: &pct,
		},
	}
	p := policyFromPodTrace(pt)
	if p == nil || p.Generation != 9 || p.SamplePercent == nil || *p.SamplePercent != 25 {
		t.Errorf("policyFromPodTrace lifted wrong: %+v", p)
	}

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Generation: 4},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Filters: []podtracev1alpha1.EventFilter{"cpu"},
		},
	}
	ps := policyFromSession(s)
	if ps == nil || ps.Generation != 4 || len(ps.Filters) != 1 {
		t.Errorf("policyFromSession lifted wrong: %+v", ps)
	}
}

// conditionHasReason reports whether the named condition exists with the
// expected Reason.
func conditionHasReason(conds []metav1.Condition, condType, reason string) bool {
	for _, c := range conds {
		if c.Type == condType {
			return c.Reason == reason
		}
	}
	return false
}
