package v1alpha1

import "strings"

// AllowSessionsFromAnnotation is the opt-in grant a TracerConfig must carry
// before PodTraceSessions in OTHER namespaces may pin it via tracerConfigRef.
// A pinned config decides where the session's (privileged, hostPID, SYS_ADMIN)
// Jobs and credential Secrets are created — its systemNamespace — so without
// this consent a tenant could place a privileged workload in a fleet namespace
// it has no access to.
const AllowSessionsFromAnnotation = "podtrace.io/allow-sessions-from"

// TracerConfigAllowsSessionFrom reports whether tc permits a session in
// sourceNamespace to pin it. Pinning is always allowed when the config lands
// its Jobs in the session's own namespace or in the operator's default
// namespace (the normal path — the "default" config lives there and every
// unpinned session uses it); any other systemNamespace is a cross-tenant
// placement and requires the config to grant sourceNamespace (or "*").
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
