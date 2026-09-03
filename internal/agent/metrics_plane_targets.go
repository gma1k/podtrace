package agent

import (
	"sort"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/tracer"
)

// MetricsPlaneConfig is the agent's view of TracerConfig.spec.agent.metrics
// as it affects attachment, rather than as it affects the metric surface.
type MetricsPlaneConfig struct {
	Enabled bool

	ExcludeNamespaces []string
}

func (c MetricsPlaneConfig) excludes(namespace string) bool {
	for _, excluded := range c.ExcludeNamespaces {
		if excluded == namespace {
			return true
		}
	}
	return false
}

// metricsPlaneCategories are the kernel event categories the continuous
// surface enables when it covers a node.
func MetricsPlaneCategories() []string {
	return metricsPlaneCategories()
}

// StartupCategories is the category set the agent wants attached the moment
// the tracer comes up, before any PodTrace has been observed.
func StartupCategories(planeEnabled bool) []string {
	if !planeEnabled {
		return []string{}
	}
	return metricsPlaneCategories()
}

func metricsPlaneCategories() []string {
	return []string{
		string(podtracev1alpha1.FilterDNS),
		string(podtracev1alpha1.FilterNet),
		string(podtracev1alpha1.FilterCPU),
	}
}

// unionCategories merges the CR-derived category set with the plane's own.
func unionCategories(fromRules []string, plane MetricsPlaneConfig) []string {
	if !plane.Enabled {
		return fromRules
	}
	seen := make(map[string]struct{}, len(fromRules)+4)
	for _, c := range fromRules {
		seen[c] = struct{}{}
	}
	for _, c := range metricsPlaneCategories() {
		seen[c] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// expandTargetsForMetricsPlane appends every local pod that no CR already
// covers, so that the plane observes the whole node.
func expandTargetsForMetricsPlane(
	existing tracer.TargetSet,
	podEntries []PodCgroupEntry,
	plane MetricsPlaneConfig,
) tracer.TargetSet {
	if !plane.Enabled {
		return existing
	}

	covered := make(map[string]struct{}, len(existing))
	for _, t := range existing {
		covered[targetIdentity(t.Namespace, t.PodName, t.ContainerName)] = struct{}{}
	}

	out := existing
	for _, entry := range podEntries {
		if entry.Pod == nil {
			continue
		}
		if plane.excludes(entry.Pod.Namespace) {
			continue
		}
		id := targetIdentity(entry.Pod.Namespace, entry.Pod.Name, entry.ContainerName)
		if _, ok := covered[id]; ok {
			continue
		}
		covered[id] = struct{}{}

		kind, name := resolveWorkload(entry.Pod)
		out = append(out, tracer.Target{
			PodName:       entry.Pod.Name,
			Namespace:     entry.Pod.Namespace,
			ContainerID:   entry.ContainerID,
			ContainerName: entry.ContainerName,
			ContainerPID:  entry.ContainerPID,
			CgroupPath:    entry.CgroupPath,
			Labels:        copyMap(entry.Pod.Labels),
			PodIP:         entry.Pod.Status.PodIP,
			OwnerKind:     kind,
			OwnerName:     name,
		})
	}
	return out
}

func targetIdentity(namespace, pod, container string) string {
	return namespace + "/" + pod + "/" + container
}

var metricsPlaneRequest = reconcile.Request{
	NamespacedName: types.NamespacedName{Name: "podtrace.io/metrics-plane"},
}
