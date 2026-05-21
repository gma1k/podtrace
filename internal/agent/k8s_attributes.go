package agent

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"

	"github.com/podtrace/podtrace/internal/events"
)

// appendK8sAttributes appends the frozen v1 enrichment attribute set
// to attrs and returns the extended slice.
func appendK8sAttributes(attrs []attribute.KeyValue, meta *events.K8sMetadata) []attribute.KeyValue {
	if meta == nil || meta.IsZero() {
		return attrs
	}
	if meta.Namespace != "" {
		attrs = append(attrs, semconv.K8SNamespaceName(meta.Namespace))
	}
	if meta.PodName != "" {
		attrs = append(attrs, semconv.K8SPodName(meta.PodName))
	}
	if meta.PodUID != "" {
		attrs = append(attrs, semconv.K8SPodUID(meta.PodUID))
	}
	if meta.NodeName != "" {
		attrs = append(attrs, semconv.K8SNodeName(meta.NodeName))
	}
	if meta.ContainerName != "" {
		attrs = append(attrs, semconv.K8SContainerName(meta.ContainerName))
	}
	attrs = appendWorkloadAttributes(attrs, meta.WorkloadKind, meta.WorkloadName)
	return attrs
}

// appendWorkloadAttributes maps (kind, name) to the most specific
// semconv key available.
func appendWorkloadAttributes(attrs []attribute.KeyValue, kind, name string) []attribute.KeyValue {
	if name == "" {
		return attrs
	}
	switch kind {
	case "Deployment":
		attrs = append(attrs, semconv.K8SDeploymentName(name))
	case "StatefulSet":
		attrs = append(attrs, semconv.K8SStatefulSetName(name))
	case "DaemonSet":
		attrs = append(attrs, semconv.K8SDaemonSetName(name))
	case "Job":
		attrs = append(attrs, semconv.K8SJobName(name))
	case "CronJob":
		attrs = append(attrs, semconv.K8SCronJobName(name))
	case "ReplicaSet":
		attrs = append(attrs, semconv.K8SReplicaSetName(name))
	case "Pod", "":
	default:
		attrs = append(attrs,
			attribute.String("k8s.workload.kind", kind),
			attribute.String("k8s.workload.name", name),
		)
	}
	return attrs
}