package operator

import (
	"encoding/json"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// The operator keeps the TracerConfig it bootstrapped in line with its own
// defaults, so an OLM upgrade moves the agents to the new image and picks up
// defaults added since, instead of running whatever the first version wrote.
// It only touches a field it wrote itself and nobody has changed since:
// Kubernetes records who last wrote each field in managedFields, and a user's
// edit moves the field to their manager. A field the user deleted leaves no
// owner at all, so bootstrapFieldsAnnotation records which fields the operator
// has written; one listed there but gone was removed on purpose and stays gone.
const (
	bootstrapFieldManager     = "podtrace"
	bootstrapSourceAnnotation = "podtrace.io/bootstrap-source"
	bootstrapFieldsAnnotation = "podtrace.io/bootstrap-fields"
)

type bootstrapField struct {
	name    string
	path    []string
	present func(*podtracev1alpha1.TracerConfig) bool
	equal   func(a, b *podtracev1alpha1.TracerConfig) bool
	copy    func(dst, src *podtracev1alpha1.TracerConfig)
}

// legacyBootstrapFields is what an operator older than the annotation wrote.
var legacyBootstrapFields = []string{"image", "agent.resources", "session.resources"}

func excludeNamespacesOf(tc *podtracev1alpha1.TracerConfig) []string {
	if tc.Spec.Agent.Metrics == nil {
		return nil
	}
	return tc.Spec.Agent.Metrics.ExcludeNamespaces
}

var bootstrapFields = []bootstrapField{
	{
		name:    "image",
		path:    []string{"spec", "image"},
		present: func(tc *podtracev1alpha1.TracerConfig) bool { return tc.Spec.Image != "" },
		equal:   func(a, b *podtracev1alpha1.TracerConfig) bool { return a.Spec.Image == b.Spec.Image },
		copy:    func(dst, src *podtracev1alpha1.TracerConfig) { dst.Spec.Image = src.Spec.Image },
	},
	{
		name:    "tolerations",
		path:    []string{"spec", "tolerations"},
		present: func(tc *podtracev1alpha1.TracerConfig) bool { return tc.Spec.Tolerations != nil },
		equal: func(a, b *podtracev1alpha1.TracerConfig) bool {
			return equality.Semantic.DeepEqual(a.Spec.Tolerations, b.Spec.Tolerations)
		},
		copy: func(dst, src *podtracev1alpha1.TracerConfig) { dst.Spec.Tolerations = src.Spec.Tolerations },
	},
	{
		name:    "agent.resources",
		path:    []string{"spec", "agent", "resources"},
		present: func(tc *podtracev1alpha1.TracerConfig) bool { return !isZeroResources(tc.Spec.Agent.Resources) },
		equal: func(a, b *podtracev1alpha1.TracerConfig) bool {
			return equality.Semantic.DeepEqual(a.Spec.Agent.Resources, b.Spec.Agent.Resources)
		},
		copy: func(dst, src *podtracev1alpha1.TracerConfig) { dst.Spec.Agent.Resources = src.Spec.Agent.Resources },
	},
	{
		name:    "session.resources",
		path:    []string{"spec", "session", "resources"},
		present: func(tc *podtracev1alpha1.TracerConfig) bool { return !isZeroResources(tc.Spec.Session.Resources) },
		equal: func(a, b *podtracev1alpha1.TracerConfig) bool {
			return equality.Semantic.DeepEqual(a.Spec.Session.Resources, b.Spec.Session.Resources)
		},
		copy: func(dst, src *podtracev1alpha1.TracerConfig) { dst.Spec.Session.Resources = src.Spec.Session.Resources },
	},
	{
		name:    "agent.metrics.excludeNamespaces",
		path:    []string{"spec", "agent", "metrics", "excludeNamespaces"},
		present: func(tc *podtracev1alpha1.TracerConfig) bool { return excludeNamespacesOf(tc) != nil },
		equal: func(a, b *podtracev1alpha1.TracerConfig) bool {
			return equality.Semantic.DeepEqual(excludeNamespacesOf(a), excludeNamespacesOf(b))
		},
		copy: func(dst, src *podtracev1alpha1.TracerConfig) {
			if dst.Spec.Agent.Metrics == nil {
				dst.Spec.Agent.Metrics = &podtracev1alpha1.AgentMetricsSpec{}
			}
			dst.Spec.Agent.Metrics.ExcludeNamespaces = excludeNamespacesOf(src)
		},
	},
}

func isZeroResources(r corev1.ResourceRequirements) bool {
	return len(r.Limits) == 0 && len(r.Requests) == 0 && len(r.Claims) == 0
}

// bootstrapFieldNames lists the fields a fresh bootstrap object sets.
func bootstrapFieldNames(tc *podtracev1alpha1.TracerConfig) string {
	var names []string
	for _, f := range bootstrapFields {
		if f.present(tc) {
			names = append(names, f.name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// writtenBootstrapFields reads which fields the operator has written.
func writtenBootstrapFields(tc *podtracev1alpha1.TracerConfig) map[string]bool {
	raw, ok := tc.Annotations[bootstrapFieldsAnnotation]
	names := legacyBootstrapFields
	if ok {
		names = strings.Split(raw, ",")
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		if n != "" {
			out[n] = true
		}
	}
	return out
}

// ownedOnlyBy reports whether manager is the only writer of path in the main
// resource (status writes are a separate subresource and do not count).
func ownedOnlyBy(entries []metav1.ManagedFieldsEntry, path []string, manager string) bool {
	owned := false
	for _, e := range entries {
		if e.Subresource != "" || e.FieldsV1 == nil || !fieldsContain(e.FieldsV1.GetRawBytes(), path) {
			continue
		}
		if e.Manager != manager {
			return false
		}
		owned = true
	}
	return owned
}

func fieldsContain(raw []byte, path []string) bool {
	var node map[string]any
	if json.Unmarshal(raw, &node) != nil {
		return false
	}
	for _, part := range path {
		next, ok := node["f:"+part].(map[string]any)
		if !ok {
			return false
		}
		node = next
	}
	return true
}

// adoptBootstrapDefaults returns existing with every field the operator still
// owns brought up to desired, and whether anything changed.
func adoptBootstrapDefaults(existing, desired *podtracev1alpha1.TracerConfig) (*podtracev1alpha1.TracerConfig, bool) {
	updated := existing.DeepCopy()
	written := writtenBootstrapFields(existing)
	changed := false
	for _, f := range bootstrapFields {
		if !f.present(desired) {
			continue
		}
		switch {
		case !f.present(existing):
			if written[f.name] {
				continue
			}
		case !ownedOnlyBy(existing.ManagedFields, f.path, bootstrapFieldManager):
			continue
		case f.equal(existing, desired):
			written[f.name] = true
			continue
		}
		f.copy(updated, desired)
		written[f.name] = true
		changed = true
	}

	names := make([]string, 0, len(written))
	for n := range written {
		names = append(names, n)
	}
	sort.Strings(names)
	record := strings.Join(names, ",")
	if existing.Annotations[bootstrapFieldsAnnotation] != record {
		if updated.Annotations == nil {
			updated.Annotations = map[string]string{}
		}
		updated.Annotations[bootstrapFieldsAnnotation] = record
		changed = true
	}
	return updated, changed
}
