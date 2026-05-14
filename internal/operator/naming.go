// Package operator implements the podtrace Kubernetes operator's control
// plane: three reconcilers that watch TracerConfig, PodTrace, and
// PodTraceSession CRs and drive the corresponding infrastructure.
//
// Naming and label conventions are centralised here so every reconciler
// produces the same resource names and selectors — agents and tests
// depend on these being stable.
package operator

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Label keys. "podtrace.io/managed-by=podtrace-operator" is the single
// source of truth for "this object is owned by the operator" — used for
// bulk cleanup and for informer filters.
const (
	LabelManagedBy      = "podtrace.io/managed-by"
	LabelComponent      = "podtrace.io/component"
	LabelTracerConfig   = "podtrace.io/tracer-config"
	LabelPodTraceName   = "podtrace.io/podtrace"
	LabelPodTraceNS     = "podtrace.io/podtrace-namespace"
	LabelSessionName    = "podtrace.io/session"
	LabelSessionNS      = "podtrace.io/session-namespace"
	LabelExporterConfig = "podtrace.io/exporter-config"
	LabelNodeName       = "podtrace.io/node"

	ManagedByValue = "podtrace-operator"

	ComponentAgent   = "agent"
	ComponentSession = "session"
	ComponentBundle  = "exporter-bundle"
)

// Condition types reported on CR .status.conditions.
const (
	ConditionReady      = "Ready"
	ConditionReconciled = "Reconciled"
	ConditionDegraded   = "Degraded"
	ConditionPaused     = "Paused"
	ConditionReportUploaded = "ReportUploaded"
)

// AgentDaemonSetName is the fixed DaemonSet name created by
// TracerConfigReconciler. Agents discover each other and the operator
// discovers them by this name — do not derive per-TracerConfig names.
func AgentDaemonSetName() string { return "podtrace-agent" }

// AgentServiceAccountName is the ServiceAccount the agent DaemonSet runs as.
func AgentServiceAccountName() string { return "podtrace-agent" }

func SessionServiceAccountName() string { return "podtrace-session" }

func SessionReportRoleName(sessionUID types.UID) string {
	return "podtrace-session-report-" + shortUID(sessionUID)
}

func SessionReportRoleBindingName(sessionUID types.UID) string {
	return "podtrace-session-report-" + shortUID(sessionUID)
}

// AgentClusterRoleName is the ClusterRole granting the agent read access to
// PodTrace CRs cluster-wide and status-patch on the same.
func AgentClusterRoleName() string { return "podtrace-agent" }

// AgentClusterRoleBindingName binds AgentClusterRoleName to AgentServiceAccountName.
func AgentClusterRoleBindingName() string { return "podtrace-agent" }

func AgentBundleRoleName() string { return "podtrace-agent-bundles" }

func AgentBundleRoleBindingName() string { return "podtrace-agent-bundles" }

func OperatorWebhookServiceName() string { return "podtrace-webhook" }

func SessionJobName(sessionUID types.UID, nodeName string) string {
	raw := fmt.Sprintf("pts-%s-%s", shortUID(sessionUID), sanitiseDNS(nodeName))
	if len(raw) > 63 {
		raw = raw[:63]
	}
	return raw
}

func ExporterBundleName(exporterUID types.UID) string {
	return "pt-bundle-" + shortUID(exporterUID)
}

const BundleAnnotationSourceRef = "podtrace.io/exporterconfig-ref"

func ManagedObjectMeta(name, namespace, component string, extraLabels map[string]string) metav1.ObjectMeta {
	labels := map[string]string{
		LabelManagedBy: ManagedByValue,
		LabelComponent: component,
	}
	for k, v := range extraLabels {
		labels[k] = v
	}
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

// shortUID returns the first 12 characters of a UID string — enough to
// stay collision-resistant within a cluster while keeping derived names
// inside Kubernetes' 63-character limit.
func shortUID(uid types.UID) string {
	s := string(uid)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func sanitiseDNS(in string) string {
	b := make([]byte, 0, len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z':
			b = append(b, byte(r))
		case r >= '0' && r <= '9':
			b = append(b, byte(r))
		case r == '-':
			b = append(b, '-')
		case r >= 'A' && r <= 'Z':
			b = append(b, byte(r+('a'-'A')))
		default:
			b = append(b, '-')
		}
	}
	// Trim leading/trailing '-' — DNS-1123 forbids them at label ends.
	start, end := 0, len(b)
	for start < end && b[start] == '-' {
		start++
	}
	for end > start && b[end-1] == '-' {
		end--
	}
	if start == end {
		return "node"
	}
	return string(b[start:end])
}
