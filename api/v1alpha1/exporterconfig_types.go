package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExporterType enumerates supported trace exporters.
// +kubebuilder:validation:Enum=otlp;jaeger;zipkin;splunk;datadog
type ExporterType string

const (
	ExporterTypeOTLP    ExporterType = "otlp"
	ExporterTypeJaeger  ExporterType = "jaeger"
	ExporterTypeZipkin  ExporterType = "zipkin"
	ExporterTypeSplunk  ExporterType = "splunk"
	ExporterTypeDataDog ExporterType = "datadog"
)

// OTLPProtocol selects the OTLP transport.
// +kubebuilder:validation:Enum=http;grpc
type OTLPProtocol string

const (
	OTLPProtocolHTTP OTLPProtocol = "http"
	OTLPProtocolGRPC OTLPProtocol = "grpc"
)

// OTLPExporter configures the OpenTelemetry OTLP exporter.
type OTLPExporter struct {
	// Endpoint of the OTLP receiver, e.g. "otel-collector.observability:4318".
	// +kubebuilder:validation:Required
	Endpoint string `json:"endpoint"`

	// Protocol selects http or grpc. Defaults to http.
	// +optional
	Protocol OTLPProtocol `json:"protocol,omitempty"`

	// Insecure disables TLS. Do not use in production.
	// +optional
	Insecure bool `json:"insecure,omitempty"`

	// Headers to attach to every export request. Secret-backed headers use
	// the HeadersFromSecret field.
	// +optional
	Headers []OTLPHeader `json:"headers,omitempty"`

	// HeadersFromSecret pulls additional headers from a Secret in the same
	// namespace. Each key in the secret becomes a header; values are used verbatim.
	// +optional
	HeadersFromSecret *LocalObjectReference `json:"headersFromSecret,omitempty"`
}

// OTLPHeader is a single literal or secret-backed OTLP header.
type OTLPHeader struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +optional
	Value string `json:"value,omitempty"`
	// +optional
	ValueFrom *SecretKeySelector `json:"valueFrom,omitempty"`
}

// JaegerExporter configures the Jaeger exporter.
//
// Agent mode ships spans to Jaeger over OTLP/HTTP, so the endpoint must
// point at Jaeger's OTLP receiver (port 4318 by default), not the legacy
// Thrift collector endpoint. See docs/tracing-exporters.md.
type JaegerExporter struct {
	// Endpoint of Jaeger's OTLP/HTTP receiver, e.g.
	// "jaeger-collector.observability:4318".
	// +kubebuilder:validation:Required
	Endpoint string `json:"endpoint"`
}

// ZipkinExporter configures the Zipkin exporter.
//
// Direct export to Zipkin is not supported in agent mode (the upstream
// OTel SDK Zipkin exporter is deprecated). To route spans to Zipkin,
// deploy an OpenTelemetry Collector with the 'zipkin' exporter and
// configure podtrace with type=otlp pointing at the Collector. See
// docs/tracing-exporters.md.
type ZipkinExporter struct {
	// Endpoint, e.g. "http://zipkin.observability:9411/api/v2/spans".
	// +kubebuilder:validation:Required
	Endpoint string `json:"endpoint"`
}

// SplunkExporter configures the Splunk HEC exporter.
type SplunkExporter struct {
	// Endpoint of the Splunk HEC receiver.
	// +kubebuilder:validation:Required
	Endpoint string `json:"endpoint"`

	// TokenSecretRef references the Splunk HEC token in a Secret in the
	// same namespace as the ExporterConfig.
	// +kubebuilder:validation:Required
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef"`
}

// DataDogExporter configures the DataDog exporter.
type DataDogExporter struct {
	Endpoint string `json:"endpoint,omitempty"`

	// Site, e.g. "datadoghq.com" or "datadoghq.eu". Defaults to datadoghq.com.
	// Used as a label for routing and (when Endpoint is empty) to derive
	// a default Endpoint pointing at a conventional DataDog Agent
	// service name.
	// +optional
	Site string `json:"site,omitempty"`

	// APIKeySecretRef references the DataDog API key in a Secret in the
	// same namespace as the ExporterConfig.
	// +kubebuilder:validation:Required
	APIKeySecretRef SecretKeySelector `json:"apiKeySecretRef"`
}

// ExporterConfigSpec configures a reusable trace exporter.
// Exactly one of the typed fields (OTLP, Jaeger, Zipkin, Splunk, DataDog)
// must be populated, and it must match the Type field.
type ExporterConfigSpec struct {
	// +kubebuilder:validation:Required
	Type ExporterType `json:"type"`

	// +optional
	OTLP *OTLPExporter `json:"otlp,omitempty"`
	// +optional
	Jaeger *JaegerExporter `json:"jaeger,omitempty"`
	// +optional
	Zipkin *ZipkinExporter `json:"zipkin,omitempty"`
	// +optional
	Splunk *SplunkExporter `json:"splunk,omitempty"`
	// +optional
	DataDog *DataDogExporter `json:"datadog,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	SamplePercent *int32 `json:"samplePercent,omitempty"`
}

// ExporterConfigStatus reports the observed state of an ExporterConfig.
type ExporterConfigStatus struct {
	// +kubebuilder:default=false
	Ready bool `json:"ready"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	ReferencedBy int32 `json:"referencedBy,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ec,categories=podtrace
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Refs",type=integer,JSONPath=`.status.referencedBy`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ExporterConfig is a reusable trace exporter configuration referenced by
// PodTrace and PodTraceSession. It decouples endpoint/credential management
// from trace intent.
type ExporterConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExporterConfigSpec   `json:"spec,omitempty"`
	Status ExporterConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExporterConfigList contains a list of ExporterConfig.
type ExporterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExporterConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes(&ExporterConfig{}, &ExporterConfigList{}))
}
