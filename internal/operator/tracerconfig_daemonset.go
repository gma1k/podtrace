package operator

import (
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// buildAgentDaemonSetSpec renders the DaemonSet.Spec for the agent
// derived from a TracerConfig. Extracted from the reconciler so unit
// tests can assert on the resulting spec without spinning envtest.
//
// Design invariants:
//
//   - The agent runs privileged (CAP_BPF + CAP_SYS_ADMIN + CAP_PERFMON)
//     and as root. The podtrace-system namespace is PSA-privileged so
//     the pod is admitted.
//   - Host mounts are kept to the minimum the tracer needs:
//     /sys/fs/bpf, /sys/kernel/btf, /proc, /sys/fs/cgroup, and the CRI
//     socket path. All read-only except /sys/fs/bpf (BPF objects
//     require RW) and /proc (read-only is enough).
//   - NODE_NAME is injected via the downward API so the agent's
//     informers can filter with fieldSelector=spec.nodeName=$NODE_NAME.
//   - PriorityClassName defaults to system-node-critical so scheduling
//     pressure does not evict the agent.
func buildAgentDaemonSetSpec(tc *podtracev1alpha1.TracerConfig, systemNS string) appsv1.DaemonSetSpec {
	selector := &metav1.LabelSelector{
		MatchLabels: map[string]string{
			LabelManagedBy:    ManagedByValue,
			LabelComponent:    ComponentAgent,
			LabelTracerConfig: tc.Name,
		},
	}

	hostPathType := corev1.HostPathDirectory
	priv := true
	runAsRoot := int64(0)

	imagePullPolicy := tc.Spec.ImagePullPolicy
	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
	}

	priorityClassName := tc.Spec.Agent.PriorityClassName
	if priorityClassName == "" {
		priorityClassName = "system-node-critical"
	}

	env := []corev1.EnvVar{
		{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{Name: "PODTRACE_PROC_BASE", Value: "/host/proc"},
	}

	if lvl := tc.Spec.Agent.LogLevel; lvl != "" {
		env = append(env, corev1.EnvVar{Name: "PODTRACE_LOG_LEVEL", Value: lvl})
	}
	if n := tc.Spec.Agent.EventBufferSize; n > 0 {
		env = append(env, corev1.EnvVar{
			Name:  "PODTRACE_EVENT_BUFFER_SIZE",
			Value: itoa(int(n)),
		})
	}

	args := []string{
		"agent",
		"--system-namespace", systemNS,
		"--tracer-config", tc.Name,
	}
	if tc.Spec.Agent.StatusReportInterval != nil {
		args = append(args, "--status-report-interval", tc.Spec.Agent.StatusReportInterval.Duration.String())
	}

	return appsv1.DaemonSetSpec{
		Selector: selector,
		UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
			Type: appsv1.RollingUpdateDaemonSetStrategyType,
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: selector.MatchLabels,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName:            AgentServiceAccountName(),
				PriorityClassName:             priorityClassName,
				HostPID:                       true, // needed for pid→cgroup traversal via /proc
				NodeSelector:                  tc.Spec.NodeSelector,
				Tolerations:                   tc.Spec.Tolerations,
				Affinity:                      tc.Spec.Affinity,
				ImagePullSecrets:              tc.Spec.ImagePullSecrets,
				TerminationGracePeriodSeconds: ptrInt64(30),
				Containers: []corev1.Container{{
					Name:            "agent",
					Image:           tc.Spec.Image,
					ImagePullPolicy: imagePullPolicy,
					Args:            args,
					Env:             env,
					Resources:       tc.Spec.Agent.Resources,
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv,
						RunAsUser:  &runAsRoot,
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{
								"BPF", "SYS_ADMIN", "PERFMON", "SYS_RESOURCE", "NET_ADMIN",
							},
						},
					},
					Ports: []corev1.ContainerPort{
						{Name: "metrics", ContainerPort: 9090, Protocol: corev1.ProtocolTCP},
						{Name: "health", ContainerPort: 9091, Protocol: corev1.ProtocolTCP},
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstrFromString("health")},
						},
						InitialDelaySeconds: 15,
						PeriodSeconds:       20,
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstrFromString("health")},
						},
						InitialDelaySeconds: 5,
						PeriodSeconds:       10,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "bpf", MountPath: "/sys/fs/bpf", MountPropagation: mountPropagationHostToContainer()},
						{Name: "btf", MountPath: "/sys/kernel/btf", ReadOnly: true},
						{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
						{Name: "cgroup", MountPath: "/sys/fs/cgroup", ReadOnly: false},
					},
				}},
				Volumes: []corev1.Volume{
					{Name: "bpf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &hostPathType}}},
					{Name: "btf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/btf", Type: &hostPathType}}},
					{Name: "proc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc", Type: &hostPathType}}},
					{Name: "cgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup", Type: &hostPathType}}},
				},
			},
		},
	}
}

// mountPropagationHostToContainer returns a pointer to
// corev1.MountPropagationHostToContainer, required for the BPF
// filesystem: without it, bpffs pins created by the agent would not be
// visible to other processes on the host.
func mountPropagationHostToContainer() *corev1.MountPropagationMode {
	mp := corev1.MountPropagationHostToContainer
	return &mp
}

func ptrInt64(v int64) *int64 { return &v }
func itoa(n int) string       { return strconv.Itoa(n) }

// intstrFromString returns an IntOrString whose StrVal names a port by
// name.
func intstrFromString(name string) intstr.IntOrString {
	return intstr.FromString(name)
}
