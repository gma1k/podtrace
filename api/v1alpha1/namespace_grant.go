package v1alpha1

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// AllowTracingFromAnnotation is the opt-in grant a Namespace must carry
// before podtrace CRs living in OTHER namespaces may trace its pods.
const AllowTracingFromAnnotation = "podtrace.io/allow-tracing-from"

// AllowTracingFromWildcard grants every source namespace.
const AllowTracingFromWildcard = "*"

// NamespaceAllowsTracingFrom reports whether the target Namespace's
// AllowTracingFromAnnotation permits CRs in sourceNamespace to trace
// its pods.
func NamespaceAllowsTracingFrom(target *corev1.Namespace, sourceNamespace string) bool {
	if target == nil || sourceNamespace == "" {
		return false
	}
	if target.Name == sourceNamespace {
		return true
	}
	grant, ok := target.Annotations[AllowTracingFromAnnotation]
	if !ok {
		return false
	}
	for _, entry := range strings.Split(grant, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == AllowTracingFromWildcard || entry == sourceNamespace {
			return true
		}
	}
	return false
}
