package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BTFMode controls how the agent resolves BTF for CO-RE.
// +kubebuilder:validation:Enum=auto;host;embedded
type BTFMode string

const (
	// BTFModeAuto prefers the host /sys/kernel/btf/vmlinux when present,
	// falling back to the embedded stub types.
	BTFModeAuto BTFMode = "auto"
	// BTFModeHost requires /sys/kernel/btf/vmlinux on the node.
	BTFModeHost BTFMode = "host"
	// BTFModeEmbedded forces the embedded stub types even when host BTF is available.
	BTFModeEmbedded BTFMode = "embedded"
)

// AgentSpec tunes the per-node tracer DaemonSet.
type AgentSpec struct {
	// Resources applied to each agent pod.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// PriorityClassName applied to agent pods. Defaults to system-node-critical
	// when unset and the priority class exists on the cluster.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// LogLevel applied to agent pods. One of: debug, info, warn, error.
	// +kubebuilder:validation:Enum=debug;info;warn;error
	// +optional
	LogLevel string `json:"logLevel,omitempty"`

	// EventBufferSize is the per-agent event channel capacity. Default 10000.
	// +kubebuilder:validation:Minimum=128
	// +optional
	EventBufferSize int32 `json:"eventBufferSize,omitempty"`

	// StatusReportInterval controls how often each agent patches PodTrace
	// status.nodeStatus. Default 30s.
	// +optional
	StatusReportInterval *metav1.Duration `json:"statusReportInterval,omitempty"`
}

// SessionRuntimeSpec tunes the per-session Job pods the operator creates.
type SessionRuntimeSpec struct {
	// Resources applied to each session Job pod.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// TTLSecondsAfterFinished default applied to session Jobs when a session
	// does not specify its own. Default 300.
	// +kubebuilder:validation:Minimum=0
	// +optional
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`

	// ActiveDeadlineSecondsOffset is added to spec.duration to compute the
	// Job's activeDeadlineSeconds (giving the Job grace to finish reporting).
	// Default 30.
	// +kubebuilder:validation:Minimum=0
	// +optional
	ActiveDeadlineSecondsOffset int32 `json:"activeDeadlineSecondsOffset,omitempty"`

	// BackoffLimit for the Job. Default 0 (fail fast).
	// +kubebuilder:validation:Minimum=0
	// +optional
	BackoffLimit *int32 `json:"backoffLimit,omitempty"`

	// MaxDuration caps spec.duration on any PodTraceSession reconciled against
	// this TracerConfig. If unset, no cap is enforced by the operator.
	// +optional
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`

	SidecarUploader bool `json:"sidecarUploader,omitempty"`
}

// TracerConfigSpec configures the tracer infrastructure. It is cluster-scoped
// because it governs a fleet-wide DaemonSet and the Jobs the operator spawns.
type TracerConfigSpec struct {
	// Image for both the agent DaemonSet and session Job pods.
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// ImagePullPolicy. Defaults to IfNotPresent.
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// ImagePullSecrets referenced by agent and session pods.
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Agent configures the DaemonSet that provides realtime tracing.
	// +optional
	Agent AgentSpec `json:"agent,omitempty"`

	// Session configures per-session Job pods spawned for PodTraceSession CRs.
	// +optional
	Session SessionRuntimeSpec `json:"session,omitempty"`

	// NodeSelector applied to agent and session pods.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations applied to agent and session pods.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity applied to agent and session pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// BTFMode controls how the agent resolves BTF.
	// +optional
	BTFMode BTFMode `json:"btfMode,omitempty"`

	// MaxConcurrentSessionsPerNode caps privileged Job pods per node.
	// Defaults to 2.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxConcurrentSessionsPerNode int32 `json:"maxConcurrentSessionsPerNode,omitempty"`

	// SystemNamespace is the namespace in which the operator creates the
	// agent DaemonSet, session Jobs, and resolved exporter bundles.
	// Defaults to "podtrace-system". Must be a Pod-Security-Admission
	// "privileged" namespace.
	// +optional
	SystemNamespace string `json:"systemNamespace,omitempty"`
}

// TracerConfigStatus reflects the observed state of a TracerConfig.
type TracerConfigStatus struct {
	// DesiredAgents is the number of nodes the agent DaemonSet targets.
	DesiredAgents int32 `json:"desiredAgents,omitempty"`

	// ReadyAgents is the number of agent pods currently Ready.
	ReadyAgents int32 `json:"readyAgents,omitempty"`

	// ActiveSessions is the number of PodTraceSession Jobs currently Running.
	ActiveSessions int32 `json:"activeSessions,omitempty"`

	// Conditions is the latest available observations.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// ObservedGeneration is the most recent generation observed.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=tc,categories=podtrace
// +kubebuilder:printcolumn:name="Desired",type=integer,JSONPath=`.status.desiredAgents`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyAgents`
// +kubebuilder:printcolumn:name="Sessions",type=integer,JSONPath=`.status.activeSessions`
// +kubebuilder:printcolumn:name="Image",type=string,priority=1,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TracerConfig is the cluster-wide infrastructure configuration for the
// podtrace operator. A single TracerConfig named "default" governs the
// fleet-wide DaemonSet and Session Jobs.
type TracerConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TracerConfigSpec   `json:"spec,omitempty"`
	Status TracerConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TracerConfigList contains a list of TracerConfig.
type TracerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TracerConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes(&TracerConfig{}, &TracerConfigList{}))
}
