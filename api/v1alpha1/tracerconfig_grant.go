package v1alpha1

import "strings"

const AllowSessionsFromAnnotation = "podtrace.io/allow-sessions-from"

// TracerConfigAllowsSessionFrom reports whether tc permits a session in
// sourceNamespace to pin it.
func TracerConfigAllowsSessionFrom(tc *TracerConfig, sourceNamespace, operatorDefaultNamespace string) bool {
	if tc == nil || sourceNamespace == "" {
		return false
	}
	target := tc.Spec.SystemNamespace
	if target == "" {
		target = operatorDefaultNamespace
	}
	if target == sourceNamespace || target == operatorDefaultNamespace {
		return true
	}
	grant, ok := tc.Annotations[AllowSessionsFromAnnotation]
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
