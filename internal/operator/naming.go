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
)

// AgentDaemonSetName is the fixed DaemonSet name created by
// TracerConfigReconciler. Agents discover each other and the operator
// discovers them by this name — do not derive per-TracerConfig names.
func AgentDaemonSetName() string { return "podtrace-agent" }

// AgentServiceAccountName is the ServiceAccount the agent DaemonSet runs as.
func AgentServiceAccountName() string { return "podtrace-agent" }

// AgentClusterRoleName is the ClusterRole granting the agent read access to
// PodTrace CRs cluster-wide and status-patch on the same.
func AgentClusterRoleName() string { return "podtrace-agent" }

// AgentClusterRoleBindingName binds AgentClusterRoleName to AgentServiceAccountName.
func AgentClusterRoleBindingName() string { return "podtrace-agent" }

// OperatorWebhookServiceName is the Service fronting the webhook server
// inside the operator Deployment. Referenced by the
// ValidatingWebhookConfiguration rendered by the Helm chart.
func OperatorWebhookServiceName() string { return "podtrace-webhook" }

// SessionJobName returns the deterministic Job name for a PodTraceSession
// on a specific node. Keeping it deterministic makes
// PodTraceSessionReconciler's fan-out idempotent — re-reconciling never
// produces a second Job on the same node.
//
// Format: pts-<session-uid>-<node-hash>, truncated to 63 chars. Using
// the session UID (not name) is mandatory because session names collide
// across namespaces but UIDs never do.
func SessionJobName(sessionUID types.UID, nodeName string) string {
	raw := fmt.Sprintf("pts-%s-%s", shortUID(sessionUID), sanitiseDNS(nodeName))
	if len(raw) > 63 {
		raw = raw[:63]
	}
	return raw
}

// ExporterBundleName returns the ConfigMap/Secret name maintained by the
// operator in the system namespace for an ExporterConfig. Agents read
// these bundles instead of the original Secrets so their RBAC stays
// scoped to podtrace-system only.
//
// Format: pt-bundle-<exporterconfig-uid>. Namespace is always
// TracerConfig.spec.systemNamespace (default "podtrace-system").
func ExporterBundleName(exporterUID types.UID) string {
	return "pt-bundle-" + shortUID(exporterUID)
}

// BundleAnnotationSourceRef is an annotation the operator puts on every
// bundle ConfigMap/Secret pointing back at the ExporterConfig that owns
// it (namespace/name). Used for audit and for reverse lookup when the
// ExporterConfig is deleted.
const BundleAnnotationSourceRef = "podtrace.io/exporterconfig-ref"

// ManagedObjectMeta returns the common ObjectMeta applied to every
// operator-managed resource (DaemonSet, Job, RBAC, Service, bundles).
// Callers augment with owner refs and optional extra labels.
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

// sanitiseDNS replaces characters that are not valid in DNS-1123 labels
// with '-'. Node names can legally contain characters like '.' which
// Kubernetes rejects in object names.
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
