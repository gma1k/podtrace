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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// createPodOnNode creates a Running Pod on the given node in the given ns.
// envtest has no kubelet, so we manually set spec.nodeName and
// status.phase=Running. That's enough for the reconciler's selector +
// node-resolution path.
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

	// Pods on two distinct nodes matching app=api.
	createPodOnNode(t, c, ns, "api-a", "node-a", map[string]string{"app": "api"})
	createPodOnNode(t, c, ns, "api-b", "node-b", map[string]string{"app": "api"})
	// Decoy pod that must NOT be included.
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

	// Jobs must be pinned to the right nodes via nodeSelector.
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

// errf is a shorthand for fmt.Errorf used inside reconcileUntil predicates.
func errf(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}
