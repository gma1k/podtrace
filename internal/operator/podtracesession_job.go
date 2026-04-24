package operator

import (
	"strconv"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func buildSessionJobSpec(s *podtracev1alpha1.PodTraceSession, tc *podtracev1alpha1.TracerConfig, node string) batchv1.JobSpec {
	completions := int32(1)
	parallelism := int32(1)

	backoffLimit := int32(0)
	ttlSeconds := int32(300)
	deadlineOffset := int32(30)
	sidecarUploader := false
	if tc != nil {
		if tc.Spec.Session.BackoffLimit != nil {
			backoffLimit = *tc.Spec.Session.BackoffLimit
		}
		if tc.Spec.Session.TTLSecondsAfterFinished != nil {
			ttlSeconds = *tc.Spec.Session.TTLSecondsAfterFinished
		}
		if tc.Spec.Session.ActiveDeadlineSecondsOffset > 0 {
			deadlineOffset = tc.Spec.Session.ActiveDeadlineSecondsOffset
		}
		sidecarUploader = tc.Spec.Session.SidecarUploader
	}

	activeDeadline := int64(s.Spec.Duration.Seconds()) + int64(deadlineOffset)

	imagePullPolicy := corev1.PullIfNotPresent
	image := ""
	var pullSecrets []corev1.LocalObjectReference
	var resources corev1.ResourceRequirements
	if tc != nil {
		image = tc.Spec.Image
		if tc.Spec.ImagePullPolicy != "" {
			imagePullPolicy = tc.Spec.ImagePullPolicy
		}
		pullSecrets = tc.Spec.ImagePullSecrets
		resources = tc.Spec.Session.Resources
	}

	priv := true
	runAsRoot := int64(0)

	args := buildDiagnoseArgs(s)
	reportTo := reportToSpecFromReportRef(s)

	volumes := []corev1.Volume{
		{Name: "bpf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf"}}},
		{Name: "btf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/btf"}}},
		{Name: "proc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
		{Name: "cgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup"}}},
		// Exporter bundle: the CLI reads bundle.yaml to resolve the
		// exporter endpoint/credentials the session should push to.
		{
			Name: "exporter",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: SessionBundleName(s.UID)},
					Optional:             pointerBool(true),
				},
			},
		},
		// Companion credential Secret, mounted only when present. The
		// volume's Optional flag keeps credential-less bundles working
		// without apiserver errors.
		{
			Name: "exporter-credential",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: SessionBundleName(s.UID),
					Optional:   pointerBool(true),
				},
			},
		},
		// Shared run dir for CLI artifacts (summary.json, report.txt)
		// and the termination-message file. EmptyDir because the
		// lifetime matches the Pod.
		{
			Name:         "rundir",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		},
	}

	mainVolumeMounts := []corev1.VolumeMount{
		{Name: "bpf", MountPath: "/sys/fs/bpf", MountPropagation: mountPropagationHostToContainer()},
		{Name: "btf", MountPath: "/sys/kernel/btf", ReadOnly: true},
		{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
		{Name: "cgroup", MountPath: "/sys/fs/cgroup", ReadOnly: false},
		{Name: "exporter", MountPath: "/etc/podtrace/exporter", ReadOnly: true},
		{Name: "exporter-credential", MountPath: "/etc/podtrace/exporter-credential", ReadOnly: true},
		{Name: "rundir", MountPath: "/var/run/podtrace"},
	}

	// --exporter-from-file is always wired because every session has a
	// bundle ConfigMap. Credential file path is an env var the CLI
	// picks up only when set.
	sessionArgs := append([]string{}, args...)
	sessionArgs = append(sessionArgs,
		"--exporter-from-file", "/etc/podtrace/exporter/bundle.yaml",
		"--summary-file", "/var/run/podtrace/summary.json",
		"--termination-message-path", "/dev/termination-log",
	)
	if reportTo != "" {
		sessionArgs = append(sessionArgs, "--report-to", reportTo)
	}

	mainEnv := []corev1.EnvVar{
		{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name:  "PODTRACE_EXPORTER_CREDENTIAL_FILE",
			Value: "/etc/podtrace/exporter-credential/credential",
		},
	}

	mainContainer := corev1.Container{
		Name:                     "podtrace",
		Image:                    image,
		ImagePullPolicy:          imagePullPolicy,
		Args:                     sessionArgs,
		Env:                      mainEnv,
		Resources:                resources,
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		SecurityContext: &corev1.SecurityContext{
			Privileged: &priv,
			RunAsUser:  &runAsRoot,
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"BPF", "SYS_ADMIN", "PERFMON", "SYS_RESOURCE", "NET_ADMIN"},
			},
		},
		VolumeMounts: mainVolumeMounts,
	}

	initContainers := buildSessionSidecar(sidecarUploader, reportTo, image, imagePullPolicy)

	return batchv1.JobSpec{
		Completions:             &completions,
		Parallelism:             &parallelism,
		BackoffLimit:            &backoffLimit,
		TTLSecondsAfterFinished: &ttlSeconds,
		ActiveDeadlineSeconds:   &activeDeadline,
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					LabelManagedBy:   ManagedByValue,
					LabelComponent:   ComponentSession,
					LabelSessionName: s.Name,
					LabelSessionNS:   s.Namespace,
					LabelNodeName:    node,
				},
			},
			Spec: corev1.PodSpec{
				RestartPolicy:      corev1.RestartPolicyNever,
				ServiceAccountName: SessionServiceAccountName(),
				NodeSelector: map[string]string{
					"kubernetes.io/hostname": node,
				},
				HostPID:           true,
				ImagePullSecrets:  pullSecrets,
				Tolerations:       tolerationsFrom(tc),
				PriorityClassName: priorityClassNameFrom(tc),
				InitContainers:    initContainers,
				Containers:        []corev1.Container{mainContainer},
				Volumes:           volumes,
			},
		},
	}
}

// buildSessionSidecar returns the native sidecar (init container with
// restartPolicy=Always) that re-uploads the session report when the
// operator's TracerConfig.spec.session.sidecarUploader flag is set.
// Returns nil when the flag is off or no report sink is configured.
//
// Native sidecar semantics (Kubernetes 1.29+) guarantee the sidecar
// starts before the main container and gets SIGTERM when the main
// container completes — the podtrace report-uploader subcommand uses
// that signal to perform a final upload.
func buildSessionSidecar(enabled bool, reportTo, image string, pullPolicy corev1.PullPolicy) []corev1.Container {
	if !enabled || reportTo == "" {
		return nil
	}
	always := corev1.ContainerRestartPolicyAlways
	return []corev1.Container{{
		Name:            "report-uploader",
		Image:           image,
		ImagePullPolicy: pullPolicy,
		RestartPolicy:   &always,
		Args: []string{
			"report-uploader",
			"--report-file", "/var/run/podtrace/report.txt",
			"--summary-file", "/var/run/podtrace/summary.json",
			"--report-to", reportTo,
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "rundir", MountPath: "/var/run/podtrace"},
		},
	}}
}

// pointerBool is a trivial helper for struct-literal initialization of
// *bool fields that Kubernetes API types require. Callers read better
// at the use site than a one-off &boolvar pattern.
func pointerBool(b bool) *bool {
	return &b
}

// buildDiagnoseArgs produces the `podtrace` CLI args that a session Job
// executes. The Job is pinned to one node, so we additionally pre-filter
// the selector/podRefs to that node at --pods time — but this first
// iteration trusts the top-level selector and lets the binary resolve
// pods itself.
func buildDiagnoseArgs(s *podtracev1alpha1.PodTraceSession) []string {
	args := []string{
		"--diagnose", s.Spec.Duration.Duration.String(),
	}
	if s.Spec.ContainerName != "" {
		args = append(args, "--container", s.Spec.ContainerName)
	}
	if len(s.Spec.Filters) > 0 {
		vals := make([]string, 0, len(s.Spec.Filters))
		for _, f := range s.Spec.Filters {
			vals = append(vals, string(f))
		}
		args = append(args, "--filter", strings.Join(vals, ","))
	}
	if s.Spec.SamplePercent != nil {
		args = append(args, "--tracing-sample-rate", strconv.FormatFloat(float64(*s.Spec.SamplePercent)/100.0, 'f', 2, 64))
	}

	// Selector → podtrace's --pod-selector flag. PodRefs → --pods.
	// Webhook guarantees exactly one of the two is set.
	if s.Spec.Selector != nil {
		args = append(args, "--pod-selector", labelSelectorToFlag(s.Spec.Selector))
		args = append(args, "--all-in-namespace", "--namespace", s.Namespace)
	}
	if len(s.Spec.PodRefs) > 0 {
		refs := make([]string, 0, len(s.Spec.PodRefs))
		for _, r := range s.Spec.PodRefs {
			if r.Namespace != "" {
				refs = append(refs, r.Namespace+"/"+r.Name)
			} else {
				refs = append(refs, s.Namespace+"/"+r.Name)
			}
		}
		args = append(args, "--pods", strings.Join(refs, ","))
	}
	return args
}

func labelSelectorToFlag(s *metav1.LabelSelector) string {
	parts := make([]string, 0, len(s.MatchLabels))
	for k, v := range s.MatchLabels {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func tolerationsFrom(tc *podtracev1alpha1.TracerConfig) []corev1.Toleration {
	if tc == nil {
		return nil
	}
	return tc.Spec.Tolerations
}

func priorityClassNameFrom(tc *podtracev1alpha1.TracerConfig) string {
	if tc == nil {
		return ""
	}
	return tc.Spec.Agent.PriorityClassName
}

// makeSessionJobRefs rolls up a list of child Jobs into the slim status
// representation carried on PodTraceSession.
func makeSessionJobRefs(jobs []batchv1.Job) []podtracev1alpha1.SessionJobRef {
	refs := make([]podtracev1alpha1.SessionJobRef, 0, len(jobs))
	for _, j := range jobs {
		node := j.Labels[LabelNodeName]
		ref := podtracev1alpha1.SessionJobRef{
			Node:      node,
			Name:      j.Name,
			Completed: j.Status.Succeeded > 0 || j.Status.Failed >= jobBackoffLimit(&j)+1,
		}
		if j.Status.StartTime != nil {
			ref.StartTime = j.Status.StartTime
		}
		if j.Status.CompletionTime != nil {
			ref.CompletionTime = j.Status.CompletionTime
		}
		if j.Status.Failed > 0 && j.Status.Succeeded == 0 {
			ref.Message = "Job failed"
		}
		refs = append(refs, ref)
	}
	return refs
}

func jobBackoffLimit(j *batchv1.Job) int32 {
	if j.Spec.BackoffLimit != nil {
		return *j.Spec.BackoffLimit
	}
	return 6 // Kubernetes default
}

// computeSessionPhase maps Job statuses to a SessionPhase.
//
//   - All succeeded         → Completed
//   - Any failed past limit → Failed
//   - Any running           → Running
//   - Otherwise             → Pending
func computeSessionPhase(jobs []batchv1.Job) podtracev1alpha1.SessionPhase {
	if len(jobs) == 0 {
		return podtracev1alpha1.SessionPhasePending
	}
	allSucceeded := true
	anyRunning := false
	anyFailedFatal := false
	for i := range jobs {
		j := &jobs[i]
		succeeded := j.Status.Succeeded > 0
		failed := j.Status.Failed > jobBackoffLimit(j)
		running := j.Status.Active > 0

		if !succeeded {
			allSucceeded = false
		}
		if failed {
			anyFailedFatal = true
		}
		if running {
			anyRunning = true
		}
	}
	switch {
	case allSucceeded:
		return podtracev1alpha1.SessionPhaseCompleted
	case anyFailedFatal:
		return podtracev1alpha1.SessionPhaseFailed
	case anyRunning:
		return podtracev1alpha1.SessionPhaseRunning
	default:
		return podtracev1alpha1.SessionPhasePending
	}
}

func isTerminal(p podtracev1alpha1.SessionPhase) bool {
	return p == podtracev1alpha1.SessionPhaseCompleted || p == podtracev1alpha1.SessionPhaseFailed
}

func anyJobStarted(jobs []batchv1.Job) bool {
	for _, j := range jobs {
		if j.Status.StartTime != nil || j.Status.Active > 0 || j.Status.Succeeded > 0 || j.Status.Failed > 0 {
			return true
		}
	}
	return false
}
