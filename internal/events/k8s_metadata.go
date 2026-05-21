package events

// K8sMetadata is the frozen Kubernetes context attached to events
// after agent-side enrichment.
type K8sMetadata struct {
	Namespace string

	PodName string

	PodUID string

	NodeName string

	ContainerName string

	WorkloadKind string

	WorkloadName string
}

// IsZero reports whether the metadata bundle contains no useful
// information.
func (m K8sMetadata) IsZero() bool {
	return m.Namespace == "" &&
		m.PodName == "" &&
		m.PodUID == "" &&
		m.NodeName == "" &&
		m.ContainerName == "" &&
		m.WorkloadKind == "" &&
		m.WorkloadName == ""
}