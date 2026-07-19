package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BTFMode controls how the agent resolves BTF for CO-RE.
// +kubebuilder:validation:Enum=auto;host;embedded
type BTFMode string

const (
	BTFModeAuto     BTFMode = "auto"
	BTFModeHost     BTFMode = "host"
	BTFModeEmbedded BTFMode = "embedded"
)

// AgentSpec tunes the per-node tracer DaemonSet.
type AgentSpec struct {
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// +kubebuilder:validation:Enum=debug;info;warn;error
	// +optional
	LogLevel string `json:"logLevel,omitempty"`

	// +kubebuilder:validation:Minimum=128
	// +optional
	EventBufferSize int32 `json:"eventBufferSize,omitempty"`

	// +optional
	StatusReportInterval *metav1.Duration `json:"statusReportInterval,omitempty"`

	// +optional
	DNSPacketCapture *bool `json:"dnsPacketCapture,omitempty"`

	// +optional
	DNSFullAnswers *bool `json:"dnsFullAnswers,omitempty"`

	// +optional
	USDT *bool `json:"usdt,omitempty"`

	// +optional
	Alerting *AgentAlertingSpec `json:"alerting,omitempty"`
}

// AgentAlertingSpec configures agent-side resource-limit alert delivery.
type AgentAlertingSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// +optional
	WebhookURL string `json:"webhookURL,omitempty"`

	// +optional
	AllowInsecureWebhook bool `json:"allowInsecureWebhook,omitempty"`
}

// RedactionSpec configures PII redaction applied to event Target and Details
// fields in the tracer, before any exporter or report sink receives them.
type RedactionSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// +optional
	RedactDNSNames bool `json:"redactDNSNames,omitempty"`

	// +optional
	// +listType=map
	// +listMapKey=name
	CustomRules []RedactionRule `json:"customRules,omitempty"`
}

// CaptureSpec selects additional L7 request/response data to capture.
type CaptureSpec struct {
	// +optional
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:items:MaxLength=32
	// +kubebuilder:validation:items:Pattern=`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`
	Headers []string `json:"headers,omitempty"`
}

// RedactionRule is a single user-supplied redaction pattern.
type RedactionRule struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Pattern string `json:"pattern"`

	// +optional
	Replace string `json:"replace,omitempty"`
}

// SessionRuntimeSpec tunes the per-session Job pods the operator creates.
type SessionRuntimeSpec struct {
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	ActiveDeadlineSecondsOffset int32 `json:"activeDeadlineSecondsOffset,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	BackoffLimit *int32 `json:"backoffLimit,omitempty"`

	// +optional
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`

	SidecarUploader bool `json:"sidecarUploader,omitempty"`
}

// TracerConfigSpec configures the tracer infrastructure. It is cluster-scoped
// because it governs a fleet-wide DaemonSet and the Jobs the operator spawns.
type TracerConfigSpec struct {
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// +optional
	Agent AgentSpec `json:"agent,omitempty"`

	// +optional
	Session SessionRuntimeSpec `json:"session,omitempty"`

	// +optional
	Redaction *RedactionSpec `json:"redaction,omitempty"`

	// +optional
	Capture *CaptureSpec `json:"capture,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// +optional
	BTFMode BTFMode `json:"btfMode,omitempty"`

	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxConcurrentSessionsPerNode int32 `json:"maxConcurrentSessionsPerNode,omitempty"`

	// +optional
	SystemNamespace string `json:"systemNamespace,omitempty"`
}

// TracerConfigStatus reflects the observed state of a TracerConfig.
type TracerConfigStatus struct {
	DesiredAgents int32 `json:"desiredAgents,omitempty"`

	ReadyAgents int32 `json:"readyAgents,omitempty"`

	ActiveSessions int32 `json:"activeSessions,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

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
// podtrace operator.
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
