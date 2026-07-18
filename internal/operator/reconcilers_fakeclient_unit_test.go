package operator

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// ─── ExporterConfigReconciler watch-handler map functions ────────────

// TestFakeReconcile_SecretToExporterConfigs verifies the Secret watch
// handler enqueues only ECs in the Secret's namespace that reference
// the changed Secret by name, and returns nil for a non-Secret object.
func TestFakeReconcile_SecretToExporterConfigs(t *testing.T) {
	const ns = "team-a"
	scheme := newOperatorScheme(t)

	referencing := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec-ref", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint:          "o:4317",
				Protocol:          podtracev1alpha1.OTLPProtocolHTTP,
				HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "creds"},
			},
		},
	}
	other := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec-other", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "o:4317", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(referencing, other).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}

	got := r.secretToExporterConfigs(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: ns},
	})
	if len(got) != 1 {
		t.Fatalf("got %d requests, want 1", len(got))
	}
	if got[0].Name != "ec-ref" || got[0].Namespace != ns {
		t.Errorf("unexpected request %+v", got[0])
	}

	if got := r.secretToExporterConfigs(context.Background(), &corev1.Pod{}); got != nil {
		t.Errorf("non-Secret input should return nil, got %v", got)
	}
}

// TestFakeReconcile_PodTraceToExporterConfig verifies the PodTrace watch
// handler maps to the referenced ExporterConfig and short-circuits on
// empty ExporterRef / wrong type.
func TestFakeReconcile_PodTraceToExporterConfig(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "ns"},
		Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"}},
	}
	got := r.podTraceToExporterConfig(context.Background(), pt)
	if len(got) != 1 || got[0].Name != "ec" || got[0].Namespace != "ns" {
		t.Fatalf("unexpected requests %+v", got)
	}

	if got := r.podTraceToExporterConfig(context.Background(), &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "ns"},
	}); got != nil {
		t.Errorf("empty ExporterRef should return nil, got %v", got)
	}

	if got := r.podTraceToExporterConfig(context.Background(), &corev1.Pod{}); got != nil {
		t.Errorf("non-PodTrace input should return nil, got %v", got)
	}
}

// TestFakeReconcile_SessionToExporterConfig mirrors the PodTrace handler
// for PodTraceSession objects.
func TestFakeReconcile_SessionToExporterConfig(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns"},
		Spec:       podtracev1alpha1.PodTraceSessionSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"}},
	}
	got := r.sessionToExporterConfig(context.Background(), s)
	if len(got) != 1 || got[0].Name != "ec" || got[0].Namespace != "ns" {
		t.Fatalf("unexpected requests %+v", got)
	}

	if got := r.sessionToExporterConfig(context.Background(), &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns"},
	}); got != nil {
		t.Errorf("empty ExporterRef should return nil, got %v", got)
	}

	if got := r.sessionToExporterConfig(context.Background(), &corev1.Pod{}); got != nil {
		t.Errorf("non-Session input should return nil, got %v", got)
	}
}

// ─── PodTraceReconciler helpers ──────────────────────────────────────

// TestFakeReconcile_NamespaceToPodTraces enqueues only PodTraces that
// declare a NamespaceSelector.
func TestFakeReconcile_NamespaceToPodTraces(t *testing.T) {
	scheme := newOperatorScheme(t)
	withSelector := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "with-sel", Namespace: "ns"},
		Spec: podtracev1alpha1.PodTraceSpec{
			ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "ec"},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}},
		},
	}
	withoutSelector := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "no-sel", Namespace: "ns"},
		Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(withSelector, withoutSelector).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}

	got := r.namespaceToPodTraces(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "any"},
	})
	if len(got) != 1 || got[0].Name != "with-sel" {
		t.Fatalf("expected only the selector-bearing PodTrace, got %+v", got)
	}
}

// TestFakeReconcile_LoadCredentialSecret covers the happy path plus both
// error branches (missing Secret, missing key).
func TestFakeReconcile_LoadCredentialSecret(t *testing.T) {
	const ns = "team-a"
	scheme := newOperatorScheme(t)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: ns},
		Data:       map[string][]byte{"token": []byte("s3cr3t")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	out, err := r.loadCredentialSecret(context.Background(), ns,
		podtracev1alpha1.SecretKeySelector{Name: "creds", Key: "token"})
	if err != nil {
		t.Fatalf("loadCredentialSecret: %v", err)
	}
	if string(out["credential"]) != "s3cr3t" {
		t.Errorf("credential = %q, want s3cr3t", out["credential"])
	}

	if _, err := r.loadCredentialSecret(context.Background(), ns,
		podtracev1alpha1.SecretKeySelector{Name: "absent", Key: "token"}); err == nil {
		t.Error("expected error for missing Secret")
	}

	if _, err := r.loadCredentialSecret(context.Background(), ns,
		podtracev1alpha1.SecretKeySelector{Name: "creds", Key: "nope"}); err == nil {
		t.Error("expected error for missing key")
	}
}

// ─── PodTraceSessionReconciler helpers ───────────────────────────────

// TestFakeReconcile_NamespaceToPodTraceSessions enqueues only non-terminal
// PodTraceSessions that declare a NamespaceSelector.
func TestFakeReconcile_NamespaceToPodTraceSessions(t *testing.T) {
	scheme := newOperatorScheme(t)
	active := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "active", Namespace: "ns"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "ec"},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}},
		},
	}
	terminal := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "done", Namespace: "ns"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "ec"},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}},
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateCompleted},
	}
	noSelector := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "no-sel", Namespace: "ns"},
		Spec:       podtracev1alpha1.PodTraceSessionSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(active, terminal, noSelector).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}

	got := r.namespaceToPodTraceSessions(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "any"},
	})
	if len(got) != 1 || got[0].Name != "active" {
		t.Fatalf("expected only the active selector-bearing session, got %+v", got)
	}
}

// TestFakeReconcile_NodesAtCapacity verifies node-capacity accounting:
// a node with cap active Jobs from OTHER sessions is over; the
// reconciling session's own Jobs and completed Jobs don't count.
func TestFakeReconcile_NodesAtCapacity(t *testing.T) {
	const ns = "team-a"
	scheme := newOperatorScheme(t)

	sessionJob := func(name, sessName, sessNS, node string, succeeded int32) *batchv1.Job {
		return &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "podtrace-system",
				Labels: map[string]string{
					LabelManagedBy:   ManagedByValue,
					LabelComponent:   ComponentSession,
					LabelSessionName: sessName,
					LabelSessionNS:   sessNS,
					LabelNodeName:    node,
				},
			},
			Status: batchv1.JobStatus{Succeeded: succeeded},
		}
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		sessionJob("j1", "other", ns, "n1", 0),
		sessionJob("j2", "other", ns, "n2", 1),
		sessionJob("j3", "self", ns, "n3", 0),
	).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	over, err := r.nodesAtCapacity(context.Background(),
		[]string{"n1", "n2", "n3"}, 1, ns, "self")
	if err != nil {
		t.Fatalf("nodesAtCapacity: %v", err)
	}
	if len(over) != 1 || over[0] != "n1" {
		t.Errorf("expected only n1 over capacity, got %v", over)
	}
}

// TestFakeReconcile_EnsureJobs creates one Job per target node in the
// system namespace and returns every Job owned by the session.
func TestFakeReconcile_EnsureJobs(t *testing.T) {
	const ns, sysNS = "team-a", "podtrace-system"
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: ns, UID: "uid-s"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}

	jobs, err := r.ensureJobs(context.Background(), s, nil, sessionTargets{Nodes: []string{"n1", "n2"}}, nil)
	if err != nil {
		t.Fatalf("ensureJobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected 2 owned Jobs, got %d", len(jobs))
	}

	for _, node := range []string{"n1", "n2"} {
		var job batchv1.Job
		key := types.NamespacedName{Name: SessionJobName(s.UID, node), Namespace: sysNS}
		if err := c.Get(context.Background(), key, &job); err != nil {
			t.Fatalf("job for %s missing: %v", node, err)
		}
		if job.Labels[LabelNodeName] != node {
			t.Errorf("job for %s has node label %q", node, job.Labels[LabelNodeName])
		}
		if len(job.Spec.Template.Spec.Containers) == 0 {
			t.Errorf("job for %s has no containers (spec not built)", node)
		}
	}

	jobs2, err := r.ensureJobs(context.Background(), s, nil, sessionTargets{Nodes: []string{"n1", "n2"}}, nil)
	if err != nil {
		t.Fatalf("second ensureJobs: %v", err)
	}
	if len(jobs2) != 2 {
		t.Errorf("expected ensureJobs to stay at 2 Jobs, got %d", len(jobs2))
	}
}

// ─── runtime.go pure helpers ─────────────────────────────────────────

func TestFakeReconcile_DefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.SystemNamespace != "podtrace-system" {
		t.Errorf("SystemNamespace = %q, want podtrace-system", opts.SystemNamespace)
	}
	if !opts.LeaderElection {
		t.Error("LeaderElection should default to true")
	}
	if opts.LeaderElectionID != "podtrace-operator.podtrace.io" {
		t.Errorf("LeaderElectionID = %q", opts.LeaderElectionID)
	}
	if opts.WebhookPort != 9443 {
		t.Errorf("WebhookPort = %d, want 9443", opts.WebhookPort)
	}
}

func TestFakeReconcile_LeaderElectionID(t *testing.T) {
	if got := leaderElectionID(Options{LeaderElectionID: "custom.id"}); got != "custom.id" {
		t.Errorf("explicit ID = %q, want custom.id", got)
	}
	if got := leaderElectionID(Options{}); got != "podtrace-operator.podtrace.io" {
		t.Errorf("empty ID should fall back to default, got %q", got)
	}
}

var _ client.Client = fake.NewClientBuilder().Build()
