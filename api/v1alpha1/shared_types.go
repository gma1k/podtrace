package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
)

// PodRef references a specific pod by namespace/name.
type PodRef struct {
	// Namespace is the namespace of the pod. If empty, defaults to the
	// namespace of the owning CR (for namespaced CRs).
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Name is the name of the pod.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// LocalObjectReference references an object in the same namespace as the referent.
type LocalObjectReference struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// SecretKeySelector selects a key from a Secret in the same namespace.
type SecretKeySelector struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// EventFilter enumerates the event categories podtrace can capture.
// +kubebuilder:validation:Enum=dns;net;fs;cpu;proc
type EventFilter string

const (
	FilterDNS  EventFilter = "dns"
	FilterNet  EventFilter = "net"
	FilterFS   EventFilter = "fs"
	FilterCPU  EventFilter = "cpu"
	FilterProc EventFilter = "proc"
)

// Thresholds control anomaly detection on the agent side.
type Thresholds struct {
	// ErrorRatePercent triggers issue detection when errors exceed this
	// percentage over the rolling window. 0-100.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	ErrorRatePercent *int32 `json:"errorRatePercent,omitempty"`

	// RTTSpikeMs triggers issue detection when network RTT exceeds this
	// value in milliseconds.
	// +kubebuilder:validation:Minimum=0
	// +optional
	RTTSpikeMs *int32 `json:"rttSpikeMs,omitempty"`

	// FSSlowMs triggers issue detection when a filesystem operation takes
	// longer than this value in milliseconds.
	// +kubebuilder:validation:Minimum=0
	// +optional
	FSSlowMs *int32 `json:"fsSlowMs,omitempty"`
}

// ReportReference describes where a session's diagnose report is persisted.
// Exactly one sink should be set.
type ReportReference struct {
	// ConfigMap in the same namespace as the session. The operator will
	// create/update it with the report payload. Use this sink for small
	// reports; ConfigMaps are capped at 1MiB of data by etcd.
	// +optional
	ConfigMap *corev1.LocalObjectReference `json:"configMap,omitempty"`

	// Secret in the same namespace as the session. Prefer this sink when the
	// report may contain sensitive hostnames/paths/payloads.
	// +optional
	Secret *corev1.LocalObjectReference `json:"secret,omitempty"`

	// ObjectStore uploads the report to a cloud bucket (s3, gs, azblob).
	// Use this sink for reports that may exceed the 1MiB ConfigMap/Secret
	// limit. Requires the session pod to be on a Kubernetes 1.29+ cluster
	// so the native sidecar restartPolicy is honoured.
	// +optional
	ObjectStore *ObjectStoreReference `json:"objectStore,omitempty"`
}

// ObjectStoreReference names a cloud-storage destination for a session
// report. When CredentialsSecretRef is unset, the uploader uses the
// cloud SDK's default credential chain (IRSA / Workload Identity /
// Managed Identity) — the cloud-native preferred path. The explicit
// Secret is the fallback for clusters without ambient credentials.
//
// Per-backend Secret key schema (all optional — missing keys defer to
// the SDK default chain):
//
//	S3:     access_key_id, secret_access_key, session_token,
//	        region, endpoint, force_path_style
//	GCS:    service_account_json, endpoint
//	Azure:  tenant_id, client_id, client_secret,
//	        account_key, endpoint
type ObjectStoreReference struct {
	// URI of the destination. Three schemes:
	//
	//   s3://bucket/key-or-prefix
	//   gs://bucket/key-or-prefix
	//   azblob://account/container/key-or-prefix
	//
	// A trailing slash means "prefix mode" — the uploader appends a
	// per-session filename (<pod-name>-<rfc3339>.txt) and an additional
	// <key>.summary.json object. Without a trailing slash, the URI's
	// path is used verbatim as the object key.
	// +kubebuilder:validation:Required
	URI string `json:"uri"`

	// CredentialsSecretRef names a Secret in the session's namespace
	// whose keys the uploader reads.
	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}
