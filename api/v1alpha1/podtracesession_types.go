package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SessionPhase represents the lifecycle phase of a PodTraceSession.
// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed
type SessionPhase string

const (
	SessionPhasePending   SessionPhase = "Pending"
	SessionPhaseRunning   SessionPhase = "Running"
	SessionPhaseCompleted SessionPhase = "Completed"
	SessionPhaseFailed    SessionPhase = "Failed"
)

// PodTraceSessionSpec defines a bounded diagnose-mode trace. The operator
// reconciles this into one privileged Job per node hosting matched pods.
type PodTraceSessionSpec struct {
	// Selector picks target pods by label. Mutually exclusive with PodRefs.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// PodRefs explicitly enumerates target pods.
	// +optional
	PodRefs []PodRef `json:"podRefs,omitempty"`

	// NamespaceSelector scopes the Selector across namespaces. When unset
	// the selector is evaluated within the session's own namespace only.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// ContainerName restricts tracing to a specific container.
	// +optional
	ContainerName string `json:"containerName,omitempty"`

	// Duration is the total wall-clock time the session should run. Required.
	// Format: Go duration, e.g. "30s", "5m". Maximum is enforced by the
	// operator against TracerConfig.spec.session.maxDuration.
	// +kubebuilder:validation:Required
	Duration metav1.Duration `json:"duration"`

	// Filters restricts the event categories captured. When empty, all are captured.
	// +optional
	Filters []EventFilter `json:"filters,omitempty"`

	// ExporterRef names an ExporterConfig in the same namespace. Required.
	// +kubebuilder:validation:Required
	ExporterRef LocalObjectReference `json:"exporterRef"`

	// Thresholds override the session's default anomaly-detection settings.
	// +optional
	Thresholds *Thresholds `json:"thresholds,omitempty"`

	// SamplePercent sets the sampling rate for exported traces, 0-100.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	SamplePercent *int32 `json:"samplePercent,omitempty"`

	// ReportRef points at where the diagnose report summary should be persisted.
	// If unset, only the exporter receives events and the session status
	// retains a small inline summary.
	// +optional
	ReportRef *ReportReference `json:"reportRef,omitempty"`

	// TTLSecondsAfterFinished cleans up the session resource after completion.
	// If unset, the operator default applies.
	// +kubebuilder:validation:Minimum=0
	// +optional
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`
}

// SessionJobRef describes a child Job created by the session reconciler.
type SessionJobRef struct {
	// Node the Job is pinned to. Unique within the array.
	// +kubebuilder:validation:Required
	Node string `json:"node"`

	// Name of the Job resource.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Completed indicates whether the Job has finished (success or failure).
	Completed bool `json:"completed"`

	// EventCount is the number of events this Job's tracer reported.
	// +optional
	EventCount int64 `json:"eventCount,omitempty"`

	// StartTime of the Job's pod.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime of the Job's pod, if finished.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// Message carries Job-level error text when Completed is true and the Job failed.
	// +optional
	Message string `json:"message,omitempty"`
}

// SessionSummary is a compact roll-up of what the session observed.
// The full report is written to ReportRef, if set.
type SessionSummary struct {
	TotalEvents    int64 `json:"totalEvents"`
	DNSEvents      int64 `json:"dnsEvents,omitempty"`
	NetEvents      int64 `json:"netEvents,omitempty"`
	FSEvents       int64 `json:"fsEvents,omitempty"`
	CPUEvents      int64 `json:"cpuEvents,omitempty"`
	ProcEvents     int64 `json:"procEvents,omitempty"`
	ErrorsDetected int32 `json:"errorsDetected,omitempty"`
}

// PodTraceSessionStatus reflects the observed state of a PodTraceSession.
type PodTraceSessionStatus struct {
	// Phase is the high-level state of the session.
	// +optional
	Phase SessionPhase `json:"phase,omitempty"`

	// StartTime is set when the first child Job enters Running.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is set when all child Jobs have finished.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// Jobs lists the per-node Job children managed by this session.
	// +optional
	// +patchMergeKey=node
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=node
	Jobs []SessionJobRef `json:"jobs,omitempty" patchStrategy:"merge" patchMergeKey:"node"`

	// Summary is a compact per-category event roll-up for this session.
	// +optional
	Summary *SessionSummary `json:"summary,omitempty"`

	// TargetNamespaces is the sorted list of namespace names the operator
	// resolved spec.namespaceSelector.
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`

	// Conditions is the latest available observations of session state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// ObservedGeneration is the most recent generation observed for this session.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pts,categories=podtrace
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Duration",type=string,JSONPath=`.spec.duration`
// +kubebuilder:printcolumn:name="Exporter",type=string,JSONPath=`.spec.exporterRef.name`
// +kubebuilder:printcolumn:name="Events",type=integer,JSONPath=`.status.summary.totalEvents`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PodTraceSession is a bounded, diagnose-mode trace. Running a session
// creates one privileged Job per node hosting a matched pod, each invoking
// `podtrace --diagnose <duration>` against the local subset.
type PodTraceSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodTraceSessionSpec   `json:"spec,omitempty"`
	Status PodTraceSessionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PodTraceSessionList contains a list of PodTraceSession.
type PodTraceSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodTraceSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PodTraceSession{}, &PodTraceSessionList{})
}
