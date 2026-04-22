package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodTraceSpec defines a continuous, realtime tracing intent over a set of pods.
// PodTrace is the continuous-observability counterpart of PodTraceSession: it
// has no bounded duration and remains active until the resource is deleted or
// paused. Agents on each node watch PodTrace resources and feed matching pods
// into their local tracer.
type PodTraceSpec struct {
	// Selector picks target pods by label. Mutually exclusive with PodRefs;
	// exactly one of the two must be set.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// PodRefs explicitly enumerates target pods.
	// +optional
	PodRefs []PodRef `json:"podRefs,omitempty"`

	// NamespaceSelector scopes the Selector across namespaces. When unset
	// the selector is evaluated within the PodTrace's own namespace only.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// ContainerName restricts tracing to a specific container within each
	// matched pod. If empty, the first container is used.
	// +optional
	ContainerName string `json:"containerName,omitempty"`

	// Filters restricts the event categories captured. When empty, all
	// categories are captured.
	// +optional
	Filters []EventFilter `json:"filters,omitempty"`

	// ExporterRef names an ExporterConfig in the same namespace. Required.
	// +kubebuilder:validation:Required
	ExporterRef LocalObjectReference `json:"exporterRef"`

	// Thresholds override the agent's default anomaly-detection settings.
	// +optional
	Thresholds *Thresholds `json:"thresholds,omitempty"`

	// SamplePercent sets the sampling rate for exported traces, 0-100.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	SamplePercent *int32 `json:"samplePercent,omitempty"`

	// Paused suspends tracing for this resource without deleting it.
	// +optional
	Paused bool `json:"paused,omitempty"`
}

// PodTraceNodeStatus reports one agent's view of this PodTrace.
type PodTraceNodeStatus struct {
	// Node is the name of the node reporting this status. Unique within the array.
	// +kubebuilder:validation:Required
	Node string `json:"node"`

	// Ready indicates the agent has successfully attached to the local matched cgroups.
	Ready bool `json:"ready"`

	// ActiveCgroups is the count of cgroups the agent is currently tracing for this PodTrace.
	ActiveCgroups int32 `json:"activeCgroups"`

	// EventsTotal is the cumulative number of events captured by this agent
	// for this PodTrace since the agent last started.
	EventsTotal int64 `json:"eventsTotal"`

	// DroppedEvents counts events that were produced by the kernel but could
	// not be forwarded to an exporter (buffer full or exporter backpressure).
	DroppedEvents int64 `json:"droppedEvents"`

	// LastHeartbeat is the time this entry was last updated by its agent.
	LastHeartbeat metav1.Time `json:"lastHeartbeat"`

	// Message provides human-readable detail, typically an error cause when Ready is false.
	// +optional
	Message string `json:"message,omitempty"`
}

// PodTraceStatus reflects the observed state of a PodTrace.
type PodTraceStatus struct {
	// Conditions is the latest available observations of the PodTrace state.
	// Common types: Ready, Reconciled, Paused, Degraded.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// NodeStatus aggregates per-node agent reports. Agents patch their own
	// entry every StatusReportInterval (see TracerConfig).
	// +optional
	// +patchMergeKey=node
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=node
	NodeStatus []PodTraceNodeStatus `json:"nodeStatus,omitempty" patchStrategy:"merge" patchMergeKey:"node"`

	// MatchedPods is the total number of pods currently matched across all nodes.
	MatchedPods int32 `json:"matchedPods,omitempty"`

	// ObservedGeneration is the most recent generation observed for this PodTrace.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pt,categories=podtrace
// +kubebuilder:printcolumn:name="Matched",type=integer,JSONPath=`.status.matchedPods`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Exporter",type=string,JSONPath=`.spec.exporterRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PodTrace is a continuous realtime eBPF trace over a dynamic set of pods.
type PodTrace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodTraceSpec   `json:"spec,omitempty"`
	Status PodTraceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PodTraceList contains a list of PodTrace.
type PodTraceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodTrace `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PodTrace{}, &PodTraceList{})
}
