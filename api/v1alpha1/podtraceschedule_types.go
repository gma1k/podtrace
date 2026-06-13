package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConcurrencyPolicy describes how the schedule reconciles overlapping
// scheduled runs. It mirrors the semantics of batch/v1.CronJob.
// +kubebuilder:validation:Enum=Allow;Forbid;Replace
type ConcurrencyPolicy string

const (
	AllowConcurrent ConcurrencyPolicy = "Allow"

	ForbidConcurrent ConcurrencyPolicy = "Forbid"

	ReplaceConcurrent ConcurrencyPolicy = "Replace"
)

// PodTraceSessionTemplateSpec describes the desired state of the
// PodTraceSession resources the schedule will produce.
type PodTraceSessionTemplateSpec struct {
	// +optional
	Metadata PodTraceSessionTemplateMetadata `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec PodTraceSessionSpec `json:"spec"`
}

// PodTraceSessionTemplateMetadata is the subset of ObjectMeta the
// schedule controller propagates to child sessions.
type PodTraceSessionTemplateMetadata struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PodTraceScheduleSpec describes a recurring PodTraceSession schedule.
type PodTraceScheduleSpec struct {
	// Schedule is the cron expression that triggers session creation.
	// Accepts the standard 5-field form ("*/5 * * * *") and the 6-field
	// form with leading seconds ("0 */5 * * * *"). Descriptors such as
	// "@hourly", "@daily" and "@every 5m" are also accepted.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Schedule string `json:"schedule"`

	// TimeZone is an IANA time-zone name (e.g. "Europe/Amsterdam") used
	// to interpret Schedule.
	// +optional
	TimeZone *string `json:"timeZone,omitempty"`

	// +kubebuilder:default=Allow
	// +optional
	ConcurrencyPolicy ConcurrencyPolicy `json:"concurrencyPolicy,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	StartingDeadlineSeconds *int64 `json:"startingDeadlineSeconds,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	// +optional
	SuccessfulSessionsHistoryLimit *int32 `json:"successfulSessionsHistoryLimit,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=1
	// +optional
	FailedSessionsHistoryLimit *int32 `json:"failedSessionsHistoryLimit,omitempty"`

	// +optional
	Suspend *bool `json:"suspend,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	MaxActiveSessions *int32 `json:"maxActiveSessions,omitempty"`

	// +kubebuilder:validation:Required
	SessionTemplate PodTraceSessionTemplateSpec `json:"sessionTemplate"`
}

// PodTraceScheduleStatus reflects the observed state of a
// PodTraceSchedule.
type PodTraceScheduleStatus struct {
	// +optional
	Active []corev1.ObjectReference `json:"active,omitempty"`

	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`

	// +optional
	LastSuccessfulTime *metav1.Time `json:"lastSuccessfulTime,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ptsch,categories=podtrace
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Suspend",type=boolean,JSONPath=`.spec.suspend`
// +kubebuilder:printcolumn:name="Active",type=string,JSONPath=`.status.active[*].name`,priority=1
// +kubebuilder:printcolumn:name="Last Schedule",type=date,JSONPath=`.status.lastScheduleTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PodTraceSchedule describes a recurring PodTraceSession. The schedule
// controller creates a new session on each cron tick, subject to the
// ConcurrencyPolicy.
type PodTraceSchedule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodTraceScheduleSpec   `json:"spec,omitempty"`
	Status PodTraceScheduleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type PodTraceScheduleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodTraceSchedule `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes(&PodTraceSchedule{}, &PodTraceScheduleList{}))
}
