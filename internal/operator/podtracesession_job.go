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
		{Name: "debugfs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/debug"}}},
		{Name: "tracefs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/tracing"}}},
		{
			Name: "exporter",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: SessionBundleName(s.UID)},
					Optional:             pointerBool(true),
				},
			},
		},
		{
			Name: "exporter-credential",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: SessionBundleName(s.UID),
					Optional:   pointerBool(true),
				},
			},
		},
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
		{Name: "debugfs", MountPath: "/sys/kernel/debug", ReadOnly: true},
		{Name: "tracefs", MountPath: "/sys/kernel/tracing", ReadOnly: true},
		{Name: "exporter", MountPath: "/etc/podtrace/exporter", ReadOnly: true},
		{Name: "exporter-credential", MountPath: "/etc/podtrace/exporter-credential", ReadOnly: true},
		{Name: "rundir", MountPath: "/var/run/podtrace"},
	}

	sessionArgs := append([]string{}, args...)
	sessionArgs = append(sessionArgs,
		"--tracing",
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
		{Name: "PODTRACE_CRITICAL_PATH", Value: "false"},
		{Name: "PODTRACE_OTLP_INSECURE", Value: "1"},
	}
	if tc != nil {
		mainEnv = append(mainEnv, redactionEnv(tc.Spec.Redaction)...)
		mainEnv = append(mainEnv, captureEnv(tc.Spec.Capture)...)
		if lvl := tc.Spec.Agent.LogLevel; lvl != "" {
			mainEnv = append(mainEnv, corev1.EnvVar{Name: "PODTRACE_LOG_LEVEL", Value: lvl})
		}
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

	initContainers := buildSessionSidecar(sidecarUploader, reportTo, image, imagePullPolicy, s)

	if vol, ok := objectStoreCredentialsVolume(s); ok {
		volumes = append(volumes, vol)
	}

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
func buildSessionSidecar(enabled bool, reportTo, image string, pullPolicy corev1.PullPolicy, s *podtracev1alpha1.PodTraceSession) []corev1.Container {
	if !enabled || reportTo == "" {
		return nil
	}
	always := corev1.ContainerRestartPolicyAlways

	mounts := []corev1.VolumeMount{
		{Name: "rundir", MountPath: "/var/run/podtrace"},
	}
	var env []corev1.EnvVar
	if _, ok := objectStoreCredentialsVolume(s); ok {
		const credsMount = "/etc/podtrace/objectstore-credentials" // #nosec G101 -- mount path, not a credential value; documented in docs/object-store-reports.md
		mounts = append(mounts, corev1.VolumeMount{
			Name:      objectStoreCredentialsVolumeName,
			MountPath: credsMount,
			ReadOnly:  true,
		})
		env = append(env, corev1.EnvVar{
			Name:  "PODTRACE_OBJECTSTORE_CREDENTIALS_DIR",
			Value: credsMount,
		})
	}

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
		Env:                      env,
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		VolumeMounts:             mounts,
	}}
}

const objectStoreCredentialsVolumeName = "objectstore-credentials"

func objectStoreCredentialsVolume(s *podtracev1alpha1.PodTraceSession) (corev1.Volume, bool) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return corev1.Volume{}, false
	}
	ref := s.Spec.ReportRef.ObjectStore.CredentialsSecretRef
	if ref == nil || ref.Name == "" {
		return corev1.Volume{}, false
	}
	return corev1.Volume{
		Name: objectStoreCredentialsVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: SessionObjectStoreCredsName(s.UID),
				Optional:   pointerBool(false),
			},
		},
	}, true
}

// pointerBool is a trivial helper for struct-literal initialization of
// *bool fields that Kubernetes API types require.
func pointerBool(b bool) *bool {
	return &b
}

// buildDiagnoseArgs produces the `podtrace` CLI args that a session Job
// executes.
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

// labelSelectorToFlag serializes the FULL selector, matchLabels and
// matchExpressions, into the string form the in-Job CLI passes to the API
// server.
func labelSelectorToFlag(s *metav1.LabelSelector) string {
	sel, err := metav1.LabelSelectorAsSelector(s)
	if err != nil {
		return ""
	}
	return sel.String()
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
			Completed: jobSucceeded(&j) || jobFailed(&j),
		}
		if j.Status.StartTime != nil {
			ref.StartTime = j.Status.StartTime
		}
		if j.Status.CompletionTime != nil {
			ref.CompletionTime = j.Status.CompletionTime
		}
		if jobFailed(&j) && !jobSucceeded(&j) {
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
	return 6
}

// jobConditionTrue reports whether the Job carries condition t with status
// True.
func jobConditionTrue(j *batchv1.Job, t batchv1.JobConditionType) bool {
	for i := range j.Status.Conditions {
		c := &j.Status.Conditions[i]
		if c.Type == t && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// jobSucceeded / jobFailed classify a Job terminally via its conditions.
func jobSucceeded(j *batchv1.Job) bool {
	return jobConditionTrue(j, batchv1.JobComplete) || j.Status.Succeeded > 0
}

func jobFailed(j *batchv1.Job) bool {
	return jobConditionTrue(j, batchv1.JobFailed) || j.Status.Failed > jobBackoffLimit(j)
}

// computeSessionState maps Job statuses to a SessionState.
//
//   - All succeeded         → Completed
//   - Any failed past limit → Failed
//   - Any running           → Running
//   - Otherwise             → Pending
//
// computeSessionState rolls Job conditions up into a session state.
// expectedJobs is the number of target nodes this reconcile fanned out to:
// the Job List comes from the informer cache, which may not yet contain a
// Job created moments ago — without the guard a freshly grown target set
// could read as "all (visible) Jobs succeeded" and terminate the session
// early, orphaning the invisible Job's results.
func computeSessionState(jobs []batchv1.Job, expectedJobs int) podtracev1alpha1.SessionState {
	if len(jobs) == 0 {
		return podtracev1alpha1.SessionStatePending
	}
	if len(jobs) < expectedJobs {
		for i := range jobs {
			if jobs[i].Status.Active > 0 {
				return podtracev1alpha1.SessionStateRunning
			}
		}
		return podtracev1alpha1.SessionStatePending
	}
	allSucceeded := true
	anyRunning := false
	anyFailedFatal := false
	for i := range jobs {
		j := &jobs[i]
		succeeded := jobSucceeded(j)
		failed := jobFailed(j)
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
		return podtracev1alpha1.SessionStateCompleted
	case anyFailedFatal:
		return podtracev1alpha1.SessionStateFailed
	case anyRunning:
		return podtracev1alpha1.SessionStateRunning
	default:
		return podtracev1alpha1.SessionStatePending
	}
}

func isTerminal(p podtracev1alpha1.SessionState) bool {
	return p == podtracev1alpha1.SessionStateCompleted || p == podtracev1alpha1.SessionStateFailed
}

func anyJobStarted(jobs []batchv1.Job) bool {
	for _, j := range jobs {
		if j.Status.StartTime != nil || j.Status.Active > 0 || j.Status.Succeeded > 0 || j.Status.Failed > 0 {
			return true
		}
	}
	return false
}
