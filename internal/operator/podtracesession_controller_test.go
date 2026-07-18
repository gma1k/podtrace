//go:build envtest
// +build envtest

package operator

import (
	"context"
	"fmt"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func createPodOnNode(t *testing.T, c client.Client, namespace, name, node string, labels map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "c", Image: "busybox"}},
		},
	}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	pod.Status.Phase = corev1.PodRunning
	if err := c.Status().Update(ctx, pod); err != nil {
		t.Fatalf("status update pod: %v", err)
	}
}

func TestPodTraceSessionReconciler_EnvtestFanOutByNode(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ensureDefaultTracerConfig(t, c)
	ensureExporterConfig(t, c, ns, "prod-otlp")

	createPodOnNode(t, c, ns, "api-a", "node-a", map[string]string{"app": "api"})
	createPodOnNode(t, c, ns, "api-b", "node-b", map[string]string{"app": "api"})
	createPodOnNode(t, c, ns, "other", "node-a", map[string]string{"app": "other"})

	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Duration:    metav1.Duration{Duration: 30 * time.Second},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if err := c.Create(ctx, session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}

	reconcileUntil(t, 10*time.Second,
		func() error {
			var list batchv1.JobList
			if err := c.List(ctx, &list, client.InNamespace(systemNS), client.MatchingLabels{
				LabelSessionName: session.Name,
				LabelSessionNS:   ns,
			}); err != nil {
				return err
			}
			if len(list.Items) != 2 {
				return errf("have %d jobs, want 2", len(list.Items))
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: session.Name, Namespace: ns}})
			return err
		},
	)

	var list batchv1.JobList
	if err := c.List(ctx, &list, client.InNamespace(systemNS), client.MatchingLabels{
		LabelSessionName: session.Name,
		LabelSessionNS:   ns,
	}); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]bool{}
	for _, j := range list.Items {
		if j.Labels[LabelNodeName] == "" {
			t.Errorf("Job %q missing node label: %+v", j.Name, j.Labels)
		}
		nodes[j.Spec.Template.Spec.NodeSelector["kubernetes.io/hostname"]] = true
	}
	if !nodes["node-a"] || !nodes["node-b"] {
		t.Errorf("Jobs not pinned to expected nodes: %v", nodes)
	}
}

func TestPodTraceSessionReconciler_CrossNamespaceGrant(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ensureDefaultTracerConfig(t, c)
	ensureExporterConfig(t, c, ns, "prod-otlp")

	victimNS := ensureLabeledNamespace(t, c, "podtrace.io/test-grant", "victim")
	createPodOnNode(t, c, victimNS, "victim", "node-victim", map[string]string{"app": "db"})

	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "escape", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs:     []podtracev1alpha1.PodRef{{Namespace: victimNS, Name: "victim"}},
			Duration:    metav1.Duration{Duration: 30 * time.Second},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if err := c.Create(ctx, session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	doReconcile := func() error {
		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: session.Name, Namespace: ns}})
		return err
	}

	for i := 0; i < 3; i++ {
		if err := doReconcile(); err != nil {
			t.Fatalf("reconcile (ungranted): %v", err)
		}
	}
	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, client.InNamespace(systemNS), client.MatchingLabels{
		LabelSessionName: session.Name, LabelSessionNS: ns,
	}); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 0 {
		t.Fatalf("ungranted cross-namespace podRef spawned %d Job(s); tenancy escape not blocked", len(jobs.Items))
	}
	assertNoSessionPodReadRBAC(t, c, victimNS, session)

	var pending podtracev1alpha1.PodTraceSession
	if err := c.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: ns}, &pending); err != nil {
		t.Fatal(err)
	}
	if pending.Status.State != podtracev1alpha1.SessionStatePending {
		t.Errorf("state = %q, want Pending while grant is absent", pending.Status.State)
	}

	grantTracingFrom(t, c, victimNS, ns)
	reconcileUntil(t, 10*time.Second,
		func() error {
			var list batchv1.JobList
			if err := c.List(ctx, &list, client.InNamespace(systemNS), client.MatchingLabels{
				LabelSessionName: session.Name, LabelSessionNS: ns,
			}); err != nil {
				return err
			}
			if len(list.Items) != 1 {
				return fmt.Errorf("have %d jobs, want 1 after grant", len(list.Items))
			}
			var role rbacv1.Role
			if err := c.Get(ctx, types.NamespacedName{
				Name: SessionPodReadRoleName(session.UID), Namespace: victimNS,
			}, &role); err != nil {
				return fmt.Errorf("pod-read Role not provisioned in %s after grant: %w", victimNS, err)
			}
			return nil
		},
		doReconcile,
	)
}

func assertNoSessionPodReadRBAC(t *testing.T, c client.Client, namespace string, s *podtracev1alpha1.PodTraceSession) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var role rbacv1.Role
	err := c.Get(ctx, types.NamespacedName{Name: SessionPodReadRoleName(s.UID), Namespace: namespace}, &role)
	if err == nil {
		t.Errorf("pod-read Role leaked into %q without a grant", namespace)
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking pod-read Role: %v", err)
	}
	var binding rbacv1.RoleBinding
	err = c.Get(ctx, types.NamespacedName{Name: SessionPodReadRoleBindingName(s.UID), Namespace: namespace}, &binding)
	if err == nil {
		t.Errorf("pod-read RoleBinding leaked into %q without a grant", namespace)
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking pod-read RoleBinding: %v", err)
	}
}

func TestPodTraceSessionReconciler_EnvtestStatusReflectsJobCompletion(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ensureDefaultTracerConfig(t, c)
	ensureExporterConfig(t, c, ns, "prod-otlp")
	createPodOnNode(t, c, ns, "only", "node-x", map[string]string{"app": "one"})
	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "one-diag", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "one"}},
			Duration:    metav1.Duration{Duration: 10 * time.Second},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if err := c.Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}

	// Reconcile until the Job appears.
	reconcileUntil(t, 10*time.Second,
		func() error {
			var jobs batchv1.JobList
			if err := c.List(ctx, &jobs, client.InNamespace(systemNS), client.MatchingLabels{
				LabelSessionName: session.Name,
			}); err != nil {
				return err
			}
			if len(jobs.Items) != 1 {
				return errf("have %d jobs, want 1", len(jobs.Items))
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: session.Name, Namespace: ns}})
			return err
		},
	)

	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, client.InNamespace(systemNS), client.MatchingLabels{
		LabelSessionName: session.Name,
	}); err != nil || len(jobs.Items) != 1 {
		t.Fatalf("expected 1 Job, got %d (err=%v)", len(jobs.Items), err)
	}
	j := &jobs.Items[0]
	j.Status.Succeeded = 1
	now := metav1.Now()
	startTime := metav1.NewTime(now.Add(-30 * time.Second))
	j.Status.StartTime = &startTime
	j.Status.CompletionTime = &now
	j.Status.Conditions = append(j.Status.Conditions,
		batchv1.JobCondition{
			Type:               batchv1.JobSuccessCriteriaMet,
			Status:             corev1.ConditionTrue,
			LastProbeTime:      now,
			LastTransitionTime: now,
			Reason:             "SuccessCriteriaMet",
		},
		batchv1.JobCondition{
			Type:               batchv1.JobComplete,
			Status:             corev1.ConditionTrue,
			LastProbeTime:      now,
			LastTransitionTime: now,
			Reason:             "JobCompleted",
			Message:            "synthetic Complete condition for envtest fixture",
		},
	)
	if err := c.Status().Update(ctx, j); err != nil {
		t.Fatalf("status update job: %v", err)
	}

	reconcileUntil(t, 10*time.Second,
		func() error {
			var got podtracev1alpha1.PodTraceSession
			if err := c.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: ns}, &got); err != nil {
				return err
			}
			if got.Status.State != podtracev1alpha1.SessionStateCompleted {
				return errf("state=%q want Completed", got.Status.State)
			}
			return nil
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: session.Name, Namespace: ns}})
			return err
		},
	)
}

func errf(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}
