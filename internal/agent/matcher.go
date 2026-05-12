package agent

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// MatchPodTraceAgainstPods returns the subset of `pods` that match the
// PodTrace's selector (or appear in its PodRefs), are currently
// schedulable for tracing (Running + container status), and live in a
// namespace permitted by the operator-resolved allowlist.
//
// The allowlist is a tri-state argument:
//
//	nil           — the bundle did not carry target_namespaces. Either
//	                the CR has no spec.namespaceSelector or the operator
//	                hasn't yet upgraded. The matcher falls back to
//	                own-namespace-only matching.
//	[]string{}    — spec.namespaceSelector was set but matched zero
//	                namespaces. No pods can match for this CR.
//	[ns, ...]     — the bundle carries the resolved allowlist; only
//	                pods in these namespaces are eligible.
func MatchPodTraceAgainstPods(pt *podtracev1alpha1.PodTrace, pods []*corev1.Pod, allowlist []string) ([]*corev1.Pod, error) {
	if pt == nil {
		return nil, fmt.Errorf("nil PodTrace")
	}
	if pt.Spec.Paused {
		return nil, nil
	}

	sel, err := buildLabelSelector(pt.Spec.Selector)
	if err != nil {
		return nil, err
	}
	podRefs := buildPodRefIndex(pt)

	var matched []*corev1.Pod
	for _, p := range pods {
		if p == nil || !isEligiblePod(p) {
			continue
		}
		if !inNamespaceScope(pt, p, allowlist) {
			continue
		}
		switch {
		case sel != nil && sel.Matches(labels.Set(p.Labels)):
			matched = append(matched, p)
		case len(podRefs) > 0:
			if _, ok := podRefs[p.Namespace+"/"+p.Name]; ok {
				matched = append(matched, p)
			}
		}
	}
	return matched, nil
}

// buildLabelSelector converts a CR LabelSelector into a live selector.
// A selector with no MatchLabels and no MatchExpressions is treated as
// "unset" rather than "match everything" — matches the intent of our
// webhook's Selector-XOR-PodRefs rule.
func buildLabelSelector(s *metav1.LabelSelector) (labels.Selector, error) {
	if s == nil {
		return nil, nil
	}
	if len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 {
		return nil, nil
	}
	return metav1.LabelSelectorAsSelector(s)
}

// buildPodRefIndex indexes spec.podRefs by "namespace/name". Entries
// without an explicit namespace inherit the CR's own namespace,
// matching the validation webhook's defaulting.
func buildPodRefIndex(pt *podtracev1alpha1.PodTrace) map[string]struct{} {
	if len(pt.Spec.PodRefs) == 0 {
		return nil
	}
	idx := make(map[string]struct{}, len(pt.Spec.PodRefs))
	for _, r := range pt.Spec.PodRefs {
		ns := r.Namespace
		if ns == "" {
			ns = pt.Namespace
		}
		idx[ns+"/"+r.Name] = struct{}{}
	}
	return idx
}

func inNamespaceScope(pt *podtracev1alpha1.PodTrace, p *corev1.Pod, allowlist []string) bool {
	if pt.Spec.NamespaceSelector == nil {
		return p.Namespace == pt.Namespace
	}
	if allowlist == nil {
		return p.Namespace == pt.Namespace
	}
	for _, ns := range allowlist {
		if p.Namespace == ns {
			return true
		}
	}
	return false
}

// isEligiblePod is the agent-side counterpart to the operator's pod
// filter: only Running pods are traceable, because Pending pods have
// no container processes yet and terminated pods have none left.
func isEligiblePod(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodRunning
}