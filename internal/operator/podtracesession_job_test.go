package operator

import (
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func newSession(mod func(*podtracev1alpha1.PodTraceSession)) *podtracev1alpha1.PodTraceSession {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "diag",
			Namespace: "default",
			UID:       "u-sess",
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Duration: metav1.Duration{Duration: 5 * time.Minute},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if mod != nil {
		mod(s)
	}
	return s
}

func TestBuildDiagnoseArgs_SelectorPath(t *testing.T) {
	args := buildDiagnoseArgs(newSession(nil))
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--diagnose 5m0s") {
		t.Errorf("missing --diagnose: %v", args)
	}
	if !strings.Contains(joined, "--pod-selector app=api") {
		t.Errorf("missing --pod-selector: %v", args)
	}
	if !strings.Contains(joined, "--all-in-namespace") {
		t.Errorf("missing --all-in-namespace: %v", args)
	}
	if !strings.Contains(joined, "--namespace default") {
		t.Errorf("missing --namespace default: %v", args)
	}
}

func TestBuildDiagnoseArgs_PodRefsPath(t *testing.T) {
	s := newSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.Selector = nil
		s.Spec.PodRefs = []podtracev1alpha1.PodRef{
			{Name: "pod-a"},                      // falls back to s.Namespace
			{Namespace: "team-b", Name: "pod-b"}, // explicit ns
		}
	})
	args := buildDiagnoseArgs(s)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--pods default/pod-a,team-b/pod-b") {
		t.Errorf("pods flag wrong: %v", args)
	}
	if strings.Contains(joined, "--pod-selector") {
		t.Errorf("selector flag must not be present on podRefs path: %v", args)
	}
}

func TestBuildDiagnoseArgs_FiltersAndSample(t *testing.T) {
	pct := int32(50)
	s := newSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.Filters = []podtracev1alpha1.EventFilter{
			podtracev1alpha1.FilterDNS,
			podtracev1alpha1.FilterNet,
		}
		s.Spec.SamplePercent = &pct
		s.Spec.ContainerName = "api"
	})
	args := buildDiagnoseArgs(s)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--filter dns,net") {
		t.Errorf("filter flag wrong: %v", args)
	}
	if !strings.Contains(joined, "--container api") {
		t.Errorf("container flag missing: %v", args)
	}
	if !strings.Contains(joined, "--tracing-sample-rate 0.50") {
		t.Errorf("sample-rate wrong: %v", args)
	}
}

func TestBuildSessionJobSpec_CoreInvariants(t *testing.T) {
	ttl := int32(600)
	backoff := int32(0)
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/podtrace/podtrace:test",
			Session: podtracev1alpha1.SessionRuntimeSpec{
				TTLSecondsAfterFinished:     &ttl,
				BackoffLimit:                &backoff,
				ActiveDeadlineSecondsOffset: 45,
			},
		},
	}
	spec := buildSessionJobSpec(newSession(nil), tc, "node-a")

	if spec.BackoffLimit == nil || *spec.BackoffLimit != 0 {
		t.Errorf("backoffLimit: %v", spec.BackoffLimit)
	}
	if spec.TTLSecondsAfterFinished == nil || *spec.TTLSecondsAfterFinished != 600 {
		t.Errorf("TTL: %v", spec.TTLSecondsAfterFinished)
	}
	// 5m + 45s = 345s
	if spec.ActiveDeadlineSeconds == nil || *spec.ActiveDeadlineSeconds != 345 {
		t.Errorf("activeDeadlineSeconds=%v want 345", spec.ActiveDeadlineSeconds)
	}
	// Pinned to the right node
	if spec.Template.Spec.NodeSelector["kubernetes.io/hostname"] != "node-a" {
		t.Errorf("nodeSelector wrong: %v", spec.Template.Spec.NodeSelector)
	}
	if spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restartPolicy=%v want Never", spec.Template.Spec.RestartPolicy)
	}
	// Image propagated
	if spec.Template.Spec.Containers[0].Image != "ghcr.io/podtrace/podtrace:test" {
		t.Errorf("image: %q", spec.Template.Spec.Containers[0].Image)
	}
	if spec.Template.Spec.ServiceAccountName != SessionServiceAccountName() {
		t.Errorf("SA=%q want %q", spec.Template.Spec.ServiceAccountName, SessionServiceAccountName())
	}
	// Main container must carry the operator-supplied session flags so
	// the CLI knows where to load the exporter bundle and emit
	// artifacts.
	args := strings.Join(spec.Template.Spec.Containers[0].Args, " ")
	if !strings.Contains(args, "--exporter-from-file /etc/podtrace/exporter/bundle.yaml") {
		t.Errorf("missing --exporter-from-file: %v", spec.Template.Spec.Containers[0].Args)
	}
	if !strings.Contains(args, "--summary-file /var/run/podtrace/summary.json") {
		t.Errorf("missing --summary-file: %v", spec.Template.Spec.Containers[0].Args)
	}
	if !strings.Contains(args, "--termination-message-path /dev/termination-log") {
		t.Errorf("missing --termination-message-path: %v", spec.Template.Spec.Containers[0].Args)
	}
	// Mount count sanity: bpf, btf, proc, cgroup, exporter, exporter-credential, rundir = 7.
	if n := len(spec.Template.Spec.Containers[0].VolumeMounts); n != 7 {
		t.Errorf("main container mounts=%d want 7", n)
	}
	// Sidecar must not be present when TracerConfig.Session.SidecarUploader is false.
	if len(spec.Template.Spec.InitContainers) != 0 {
		t.Errorf("sidecar should be disabled by default: %d init containers", len(spec.Template.Spec.InitContainers))
	}
}

func TestBuildSessionJobSpec_SidecarOptedIn(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/podtrace/podtrace:test",
			Session: podtracev1alpha1.SessionRuntimeSpec{
				SidecarUploader: true,
			},
		},
	}
	s := newSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
			ConfigMap: &corev1.LocalObjectReference{Name: "rpt"},
		}
	})
	spec := buildSessionJobSpec(s, tc, "node-a")

	if len(spec.Template.Spec.InitContainers) != 1 {
		t.Fatalf("sidecar not emitted: %d init containers", len(spec.Template.Spec.InitContainers))
	}
	side := spec.Template.Spec.InitContainers[0]
	if side.Name != "report-uploader" {
		t.Errorf("sidecar name=%q", side.Name)
	}
	if side.RestartPolicy == nil || *side.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Errorf("sidecar restartPolicy must be Always: %+v", side.RestartPolicy)
	}
	argsStr := strings.Join(side.Args, " ")
	if !strings.Contains(argsStr, "report-uploader") || !strings.Contains(argsStr, "--report-to configmap/default/rpt") {
		t.Errorf("sidecar args wrong: %v", side.Args)
	}
}

func TestBuildSessionJobSpec_SidecarSuppressedWithoutReportRef(t *testing.T) {
	// Even when SidecarUploader is on, there is nothing to upload
	// without a report sink — the sidecar must be suppressed.
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/podtrace/podtrace:test",
			Session: podtracev1alpha1.SessionRuntimeSpec{
				SidecarUploader: true,
			},
		},
	}
	spec := buildSessionJobSpec(newSession(nil), tc, "node-a")
	if len(spec.Template.Spec.InitContainers) != 0 {
		t.Errorf("sidecar should be suppressed without reportRef: %d", len(spec.Template.Spec.InitContainers))
	}
}

func TestComputeSessionPhase_Transitions(t *testing.T) {
	succeededJob := batchv1.Job{Status: batchv1.JobStatus{Succeeded: 1}}
	failedJob := batchv1.Job{Status: batchv1.JobStatus{Failed: 7 /*> default backoffLimit 6*/}}
	runningJob := batchv1.Job{Status: batchv1.JobStatus{Active: 1}}
	pendingJob := batchv1.Job{}

	cases := []struct {
		name string
		jobs []batchv1.Job
		want podtracev1alpha1.SessionPhase
	}{
		{"empty-pending", nil, podtracev1alpha1.SessionPhasePending},
		{"all-succeeded", []batchv1.Job{succeededJob, succeededJob}, podtracev1alpha1.SessionPhaseCompleted},
		{"any-fatal-failed", []batchv1.Job{succeededJob, failedJob}, podtracev1alpha1.SessionPhaseFailed},
		{"any-running", []batchv1.Job{pendingJob, runningJob}, podtracev1alpha1.SessionPhaseRunning},
		{"pending-only", []batchv1.Job{pendingJob, pendingJob}, podtracev1alpha1.SessionPhasePending},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := computeSessionPhase(tc.jobs); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestMakeSessionJobRefs_CompletionMarker(t *testing.T) {
	jobs := []batchv1.Job{{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "pts-u-sess-node-a",
			Labels: map[string]string{LabelNodeName: "node-a"},
		},
		Status: batchv1.JobStatus{Succeeded: 1},
	}, {
		ObjectMeta: metav1.ObjectMeta{
			Name:   "pts-u-sess-node-b",
			Labels: map[string]string{LabelNodeName: "node-b"},
		},
		Status: batchv1.JobStatus{Active: 1},
	}}
	refs := makeSessionJobRefs(jobs)
	if len(refs) != 2 {
		t.Fatalf("len=%d want 2", len(refs))
	}
	if !refs[0].Completed || refs[1].Completed {
		t.Errorf("completion flags wrong: %+v", refs)
	}
}

func TestAnyJobStarted(t *testing.T) {
	start := metav1.Now()
	if anyJobStarted([]batchv1.Job{{}, {}}) {
		t.Error("no started jobs should return false")
	}
	if !anyJobStarted([]batchv1.Job{{Status: batchv1.JobStatus{StartTime: &start}}}) {
		t.Error("StartTime set should return true")
	}
	if !anyJobStarted([]batchv1.Job{{Status: batchv1.JobStatus{Active: 1}}}) {
		t.Error("Active pod should return true")
	}
}

func TestIsTerminal(t *testing.T) {
	if !isTerminal(podtracev1alpha1.SessionPhaseCompleted) {
		t.Error("Completed should be terminal")
	}
	if !isTerminal(podtracev1alpha1.SessionPhaseFailed) {
		t.Error("Failed should be terminal")
	}
	if isTerminal(podtracev1alpha1.SessionPhaseRunning) {
		t.Error("Running must not be terminal")
	}
	if isTerminal(podtracev1alpha1.SessionPhasePending) {
		t.Error("Pending must not be terminal")
	}
}
