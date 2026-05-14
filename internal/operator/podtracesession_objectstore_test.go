package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// sessionWithObjectStore returns a minimal PodTraceSession whose
// reportRef points at an ObjectStore.
func sessionWithObjectStore(credsName string) *podtracev1alpha1.PodTraceSession {
	ref := &podtracev1alpha1.ObjectStoreReference{URI: "s3://my-bucket/reports/"}
	if credsName != "" {
		ref.CredentialsSecretRef = &corev1.LocalObjectReference{Name: credsName}
	}
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "default", UID: "u-sess"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Duration:    metav1.Duration{Duration: time.Minute},
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
			ReportRef:   &podtracev1alpha1.ReportReference{ObjectStore: ref},
		},
	}
}

// TestBuildSessionJobSpec_ObjectStoreSidecarWiredWithCredentialsSecret
// verifies the operator (a) renders the report-uploader sidecar with
// the resolved ObjectStore URI in --report-to, (b) attaches the
// CredentialsSecretRef Secret as a Volume on the pod, and (c) mounts
// that volume on the sidecar only (not the main container).
func TestBuildSessionJobSpec_ObjectStoreSidecarWiredWithCredentialsSecret(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:test",
			Session: podtracev1alpha1.SessionRuntimeSpec{
				SidecarUploader: true,
			},
		},
	}
	spec := buildSessionJobSpec(sessionWithObjectStore("s3-creds"), tc, "node-a")

	if got := len(spec.Template.Spec.InitContainers); got != 1 {
		t.Fatalf("init containers = %d, want 1", got)
	}
	sc := spec.Template.Spec.InitContainers[0]
	if sc.Name != reportUploaderContainerName {
		t.Errorf("sidecar name = %q, want %q", sc.Name, reportUploaderContainerName)
	}
	args := strings.Join(sc.Args, " ")
	if !strings.Contains(args, "--report-to s3://my-bucket/reports/") {
		t.Errorf("sidecar args missing ObjectStore URI: %v", sc.Args)
	}

	wantCopyName := SessionObjectStoreCredsName(sessionWithObjectStore("s3-creds").UID)
	var foundVol bool
	for _, v := range spec.Template.Spec.Volumes {
		if v.Name == objectStoreCredentialsVolumeName {
			foundVol = true
			if v.Secret == nil || v.Secret.SecretName != wantCopyName {
				t.Errorf("credentials volume secret = %+v, want secretName=%s", v.Secret, wantCopyName)
			}
		}
	}
	if !foundVol {
		t.Error("pod missing objectstore-credentials Volume")
	}

	// (c) Mount on sidecar only.
	var sidecarMount bool
	for _, m := range sc.VolumeMounts {
		if m.Name == objectStoreCredentialsVolumeName {
			sidecarMount = true
			if m.MountPath != "/etc/podtrace/objectstore-credentials" {
				t.Errorf("mount path = %q", m.MountPath)
			}
		}
	}
	if !sidecarMount {
		t.Error("sidecar missing credentials volume mount")
	}
	for _, m := range spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == objectStoreCredentialsVolumeName {
			t.Error("main container must NOT mount the objectstore-credentials volume")
		}
	}

	var sawEnv bool
	for _, e := range sc.Env {
		if e.Name == "PODTRACE_OBJECTSTORE_CREDENTIALS_DIR" {
			sawEnv = true
			if e.Value != "/etc/podtrace/objectstore-credentials" {
				t.Errorf("env value = %q", e.Value)
			}
		}
	}
	if !sawEnv {
		t.Error("sidecar missing PODTRACE_OBJECTSTORE_CREDENTIALS_DIR env var")
	}
}

// TestBuildSessionJobSpec_ObjectStoreAmbientCreds: with no
// CredentialsSecretRef the sidecar still renders (ambient creds), but
// the Volume + mount + env var must NOT be present.
func TestBuildSessionJobSpec_ObjectStoreAmbientCreds(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:test",
			Session: podtracev1alpha1.SessionRuntimeSpec{
				SidecarUploader: true,
			},
		},
	}
	spec := buildSessionJobSpec(sessionWithObjectStore(""), tc, "node-a")
	if got := len(spec.Template.Spec.InitContainers); got != 1 {
		t.Fatalf("init containers = %d, want 1 (ambient creds still uses the sidecar)", got)
	}
	for _, v := range spec.Template.Spec.Volumes {
		if v.Name == objectStoreCredentialsVolumeName {
			t.Error("no CredentialsSecretRef -> no credentials Volume should be attached")
		}
	}
	for _, m := range spec.Template.Spec.InitContainers[0].VolumeMounts {
		if m.Name == objectStoreCredentialsVolumeName {
			t.Error("no CredentialsSecretRef -> no credentials mount on sidecar")
		}
	}
}

// TestHarvestReportLocation walks the table of pod sidecar states the
// operator can observe and asserts applyReportUploadStatus persists the
// right condition + reportLocation.
func TestHarvestReportLocation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1: %v", err)
	}

	mkPod := func(state corev1.ContainerState) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "diag-pod",
				Namespace: "podtrace-system",
				Labels: map[string]string{
					LabelSessionName: "diag",
					LabelSessionNS:   "default",
				},
			},
			Status: corev1.PodStatus{
				InitContainerStatuses: []corev1.ContainerStatus{
					{Name: reportUploaderContainerName, State: state},
				},
			},
		}
	}

	cases := []struct {
		name         string
		pod          *corev1.Pod
		wantTerm     bool
		wantOK       bool
		wantURI      string
		wantCondStat metav1.ConditionStatus
	}{
		{
			name: "sidecar-still-running",
			pod: mkPod(corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()},
			}),
			wantTerm:     false,
			wantCondStat: metav1.ConditionUnknown,
		},
		{
			name: "sidecar-succeeded",
			pod: mkPod(corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: 0,
					Message:  "s3://b/reports/sess.txt",
				},
			}),
			wantTerm:     true,
			wantOK:       true,
			wantURI:      "s3://b/reports/sess.txt",
			wantCondStat: metav1.ConditionTrue,
		},
		{
			name: "sidecar-failed",
			pod: mkPod(corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: 1,
					Message:  "upload report: dial tcp: lookup b: no such host",
				},
			}),
			wantTerm:     true,
			wantOK:       false,
			wantURI:      "upload report: dial tcp: lookup b: no such host",
			wantCondStat: metav1.ConditionFalse,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := sessionWithObjectStore("")
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.pod).Build()
			uri, term, ok, err := harvestReportLocation(context.Background(), c, s, "podtrace-system")
			if err != nil {
				t.Fatalf("harvest: %v", err)
			}
			if term != tc.wantTerm || ok != tc.wantOK || uri != tc.wantURI {
				t.Errorf("got (uri=%q, term=%v, ok=%v); want (uri=%q, term=%v, ok=%v)",
					uri, term, ok, tc.wantURI, tc.wantTerm, tc.wantOK)
			}
			applyReportUploadStatus(s, uri, term, ok)
			var got *metav1.Condition
			for i := range s.Status.Conditions {
				if s.Status.Conditions[i].Type == ConditionReportUploaded {
					got = &s.Status.Conditions[i]
				}
			}
			if got == nil {
				t.Fatal("ReportUploaded condition not set")
			}
			if got.Status != tc.wantCondStat {
				t.Errorf("condition status = %q, want %q", got.Status, tc.wantCondStat)
			}
			if tc.wantOK && s.Status.ReportLocation != tc.wantURI {
				t.Errorf("status.reportLocation = %q, want %q", s.Status.ReportLocation, tc.wantURI)
			}
			if !tc.wantOK && s.Status.ReportLocation != "" {
				t.Errorf("status.reportLocation must stay empty on failure, got %q", s.Status.ReportLocation)
			}
		})
	}
}

// TestHarvestReportLocation_NonObjectStoreIsNoop confirms the harvester
// silently returns nothing for sessions that don't use ObjectStore.
func TestHarvestReportLocation_NonObjectStoreIsNoop(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{
				ConfigMap: &corev1.LocalObjectReference{Name: "rpt"},
			},
		},
	}
	uri, term, ok, err := harvestReportLocation(context.Background(), c, s, "podtrace-system")
	if err != nil || uri != "" || term || ok {
		t.Errorf("expected silent no-op, got uri=%q term=%v ok=%v err=%v", uri, term, ok, err)
	}
	applyReportUploadStatus(s, uri, term, ok)
	for _, c := range s.Status.Conditions {
		if c.Type == ConditionReportUploaded {
			t.Errorf("non-ObjectStore session must not get a ReportUploaded condition: %+v", c)
		}
	}
}

// TestPodTraceSessionReconciler_RejectsBadObjectStoreURI confirms the
// operator-side defense-in-depth check: even when the validating
// webhook is off (the chart's default), a malformed ObjectStore URI
// must not produce a session Job that crash-loops the sidecar.
func TestPodTraceSessionReconciler_RejectsBadObjectStoreURI(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1: %v", err)
	}
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatalf("batchv1: %v", err)
	}

	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad",
			Namespace: "default",
			Finalizers: []string{"podtrace.io/cleanup"},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
			ReportRef: &podtracev1alpha1.ReportReference{
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{
					URI: "ftp://nope/k", // unsupported scheme
				},
			},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "bad", Namespace: "default"},
	}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: "bad", Namespace: "default"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	var deg *metav1.Condition
	for i := range got.Status.Conditions {
		if got.Status.Conditions[i].Type == ConditionDegraded {
			deg = &got.Status.Conditions[i]
		}
	}
	if deg == nil {
		t.Fatal("Degraded condition not set")
	}
	if deg.Status != metav1.ConditionTrue || deg.Reason != "ObjectStoreURIInvalid" {
		t.Errorf("Degraded = (%s, %s); want (True, ObjectStoreURIInvalid). Message: %q", deg.Status, deg.Reason, deg.Message)
	}
	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs.Items) > 0 {
		t.Errorf("expected 0 Jobs for a malformed-URI session, got %d", len(jobs.Items))
	}
}

var _ client.Client = nil