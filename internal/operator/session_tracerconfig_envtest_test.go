//go:build envtest
// +build envtest

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

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func createSessionFixture(t *testing.T, c client.Client, ns, node string, mutate func(*podtracev1alpha1.PodTraceSession)) *podtracev1alpha1.PodTraceSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: ns, Labels: map[string]string{"app": "target"}},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "app", Image: "busybox:1.36"}},
		},
	}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	pod.Status.Phase = corev1.PodRunning
	if err := c.Status().Update(ctx, pod); err != nil {
		t.Fatalf("set pod Running: %v", err)
	}

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
	if err := c.Create(ctx, ec); err != nil {
		t.Fatalf("create exporterconfig: %v", err)
	}

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "target"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
	if mutate != nil {
		mutate(s)
	}
	if err := c.Create(ctx, s); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return s
}

func sessionJobImage(t *testing.T, c client.Client, ns, node string, uid types.UID) (*batchv1.Job, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var job batchv1.Job
	key := types.NamespacedName{Name: SessionJobName(uid, node), Namespace: ns}
	if err := c.Get(ctx, key, &job); err != nil {
		t.Fatalf("get session Job %s: %v", key, err)
	}
	if len(job.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("session Job %s has no containers", key)
	}
	return &job, job.Spec.Template.Spec.Containers[0].Image
}

func reconcileSessionUntilSettled(t *testing.T, r *PodTraceSessionReconciler, ns, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// The first pass only stamps the finalizer and requeues; the work
	// happens on the next one.
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
		}); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
}

func TestEnvtestSessionPicksTheFleetOfItsNode(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ensureDefaultTracerConfig(t, c)

	createFleetNode(t, c, "sess-regulated", map[string]string{"pool": "sess-regulated"})
	createFleetConfig(t, c, "sess-regulated-fleet", podtracev1alpha1.TracerConfigSpec{
		Image:        "ghcr.io/gma1k/podtrace:regulated",
		NodeSelector: map[string]string{"pool": "sess-regulated"},
	})

	s := createSessionFixture(t, c, ns, "sess-regulated", nil)

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	reconcileSessionUntilSettled(t, r, ns, s.Name)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var created podtracev1alpha1.PodTraceSession
	if err := c.Get(ctx, types.NamespacedName{Name: s.Name, Namespace: ns}, &created); err != nil {
		t.Fatal(err)
	}

	job, image := sessionJobImage(t, c, systemNS, "sess-regulated", created.UID)
	if image != "ghcr.io/gma1k/podtrace:regulated" {
		t.Errorf("session Job image = %q, want the node's own fleet image; falling back to default is the false promise this feature exists to close", image)
	}
	if got := job.Labels[LabelTracerConfig]; got != "sess-regulated-fleet" {
		t.Errorf("Job %s label = %q, want sess-regulated-fleet", LabelTracerConfig, got)
	}
}

func TestEnvtestSessionRefOverridesNodeFleet(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ensureDefaultTracerConfig(t, c)

	createFleetNode(t, c, "sess-pinned", map[string]string{"pool": "sess-pinned"})
	createFleetConfig(t, c, "sess-pinned-fleet", podtracev1alpha1.TracerConfigSpec{
		Image:        "ghcr.io/gma1k/podtrace:pinned",
		NodeSelector: map[string]string{"pool": "sess-pinned"},
	})

	s := createSessionFixture(t, c, ns, "sess-pinned", func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.TracerConfigRef = &podtracev1alpha1.LocalObjectReference{Name: "default"}
	})

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	reconcileSessionUntilSettled(t, r, ns, s.Name)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var created podtracev1alpha1.PodTraceSession
	if err := c.Get(ctx, types.NamespacedName{Name: s.Name, Namespace: ns}, &created); err != nil {
		t.Fatal(err)
	}

	_, image := sessionJobImage(t, c, systemNS, "sess-pinned", created.UID)
	if image != "ghcr.io/gma1k/podtrace:test" {
		t.Errorf("session Job image = %q, want the pinned default config's image", image)
	}
}

func TestEnvtestSessionFailsWhenNothingResolves(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var existing podtracev1alpha1.TracerConfigList
	if err := c.List(ctx, &existing); err != nil {
		t.Fatal(err)
	}
	for i := range existing.Items {
		if err := c.Delete(ctx, &existing.Items[i]); err != nil {
			t.Fatalf("clear TracerConfigs: %v", err)
		}
	}
	t.Cleanup(func() { ensureDefaultTracerConfig(t, c) })

	createFleetNode(t, c, "sess-orphan", nil)
	s := createSessionFixture(t, c, ns, "sess-orphan", nil)

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	reconcileSessionUntilSettled(t, r, ns, s.Name)

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(ctx, types.NamespacedName{Name: s.Name, Namespace: ns}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %q, want Failed rather than a Job with an empty image", got.Status.State)
	}
	cond := findCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "TracerConfigUnresolved" {
		t.Errorf("want Degraded/TracerConfigUnresolved, got %+v", got.Status.Conditions)
	}

	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, client.InNamespace(systemNS), client.MatchingLabels{
		LabelSessionName: s.Name, LabelSessionNS: ns,
	}); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("no Job may be created when no config resolves, got %d", len(jobs.Items))
	}
}
