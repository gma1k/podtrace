// Package fleet resolves which agent fleet — that is, which TracerConfig —
// targets which node.
package fleet

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// daemonSetImplicitTolerations are the taints the DaemonSet controller
// tolerates on every daemon pod it creates, whether or not the pod template
// asks for them.
var daemonSetImplicitTolerations = []corev1.Toleration{
	{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists},
	{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists},
	{Key: "node.kubernetes.io/disk-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/pid-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/unschedulable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "node.kubernetes.io/network-unavailable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
}

// maxReportedContestedNodes bounds how many node names a Conflict message
// spells out.
const maxReportedContestedNodes = 5

type Partition struct {
	Matched   map[string][]string
	Contested map[string][]string
	Winner    map[string]string
	Rivals    map[string][]string
}

// ComputePartition resolves which TracerConfigs target which nodes and
// where they collide.
func ComputePartition(configs []podtracev1alpha1.TracerConfig, nodes []corev1.Node) Partition {
	p := Partition{
		Matched:   map[string][]string{},
		Contested: map[string][]string{},
		Winner:    map[string]string{},
		Rivals:    map[string][]string{},
	}

	rivalSets := map[string]map[string]struct{}{}
	for i := range configs {
		name := configs[i].Name
		p.Matched[name] = nil
		rivalSets[name] = map[string]struct{}{}
	}

	for i := range nodes {
		node := &nodes[i]
		var claimants []*podtracev1alpha1.TracerConfig
		for j := range configs {
			if NodeTargetedBy(node, &configs[j]) {
				claimants = append(claimants, &configs[j])
			}
		}
		if len(claimants) == 0 {
			continue
		}

		best := claimants[0]
		for _, c := range claimants[1:] {
			if Outranks(c, best) {
				best = c
			}
		}
		p.Winner[node.Name] = best.Name

		for _, c := range claimants {
			p.Matched[c.Name] = append(p.Matched[c.Name], node.Name)
			if len(claimants) == 1 {
				continue
			}
			p.Contested[c.Name] = append(p.Contested[c.Name], node.Name)
			for _, other := range claimants {
				if other.Name != c.Name {
					rivalSets[c.Name][other.Name] = struct{}{}
				}
			}
		}
	}

	for name, set := range rivalSets {
		if len(set) == 0 {
			continue
		}
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		p.Rivals[name] = names
	}
	for name := range p.Matched {
		sort.Strings(p.Matched[name])
		sort.Strings(p.Contested[name])
	}
	return p
}

// ConflictMessage renders the Conflict condition message for one config, or
// "" when that config is uncontested.
func (p Partition) ConflictMessage(name string) string {
	contested := p.Contested[name]
	if len(contested) == 0 {
		return ""
	}

	shown := contested
	suffix := ""
	if len(shown) > maxReportedContestedNodes {
		shown = shown[:maxReportedContestedNodes]
		suffix = fmt.Sprintf(" (+%d more)", len(contested)-maxReportedContestedNodes)
	}

	var wins, loses []string
	for _, node := range contested {
		if p.Winner[node] == name {
			wins = append(wins, node)
		} else {
			loses = append(loses, node)
		}
	}

	outcome := fmt.Sprintf("the highest priority on %d of them", len(wins))
	switch {
	case len(wins) == 0:
		outcome = "outranked on all of them"
	case len(loses) == 0:
		outcome = "the highest priority on all of them"
	}

	return fmt.Sprintf(
		"shares node(s) %s%s with TracerConfig %s; this config is %s. "+
			"Both agent DaemonSets run on a contested node, so its events are "+
			"counted once per fleet — give the configs disjoint nodeSelectors, "+
			"or set spec.fleetPriority to record which should win",
		strings.Join(shown, ", "), suffix,
		strings.Join(p.Rivals[name], ", "),
		outcome)
}

// Outranks reports whether a beats b for a node both target: explicit
// spec.fleetPriority, then specificity, then the older resource, then the
// lexicographically smaller name.
func Outranks(a, b *podtracev1alpha1.TracerConfig) bool {
	if a.Spec.FleetPriority != b.Spec.FleetPriority {
		return a.Spec.FleetPriority > b.Spec.FleetPriority
	}
	if aWide, bWide := IsClusterWide(&a.Spec), IsClusterWide(&b.Spec); aWide != bWide {
		return !aWide
	}
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Name < b.Name
}

// IsClusterWide reports whether a config declines to constrain its fleet to
// a subset of nodes, so it targets every node it tolerates.
func IsClusterWide(spec *podtracev1alpha1.TracerConfigSpec) bool {
	if len(spec.NodeSelector) > 0 {
		return false
	}
	if spec.Affinity == nil || spec.Affinity.NodeAffinity == nil {
		return true
	}
	required := spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	return required == nil || len(required.NodeSelectorTerms) == 0
}

// NodeTargetedBy reports whether the agent DaemonSet built from tc would be
// scheduled onto node, nodeSelector, required node affinity, and taints all
// have to agree, exactly as they do for the real DaemonSet controller.
func NodeTargetedBy(node *corev1.Node, tc *podtracev1alpha1.TracerConfig) bool {
	for k, v := range tc.Spec.NodeSelector {
		if node.Labels[k] != v {
			return false
		}
	}
	if !nodeMatchesRequiredAffinity(node, tc.Spec.Affinity) {
		return false
	}
	return taintsTolerated(node.Spec.Taints, tc.Spec.Tolerations)
}

func nodeMatchesRequiredAffinity(node *corev1.Node, affinity *corev1.Affinity) bool {
	if affinity == nil || affinity.NodeAffinity == nil {
		return true
	}
	required := affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	if required == nil || len(required.NodeSelectorTerms) == 0 {
		return true
	}
	for i := range required.NodeSelectorTerms {
		if nodeSelectorTermMatches(node, &required.NodeSelectorTerms[i]) {
			return true
		}
	}
	return false
}

func nodeSelectorTermMatches(node *corev1.Node, term *corev1.NodeSelectorTerm) bool {
	if len(term.MatchExpressions) == 0 && len(term.MatchFields) == 0 {
		return false
	}
	for i := range term.MatchExpressions {
		req := &term.MatchExpressions[i]
		value, present := node.Labels[req.Key]
		if !requirementMatches(req, value, present) {
			return false
		}
	}
	for i := range term.MatchFields {
		req := &term.MatchFields[i]
		if req.Key != "metadata.name" {
			return false
		}
		if !requirementMatches(req, node.Name, true) {
			return false
		}
	}
	return true
}

func requirementMatches(req *corev1.NodeSelectorRequirement, value string, present bool) bool {
	switch req.Operator {
	case corev1.NodeSelectorOpIn:
		return present && slices.Contains(req.Values, value)
	case corev1.NodeSelectorOpNotIn:
		return !present || !slices.Contains(req.Values, value)
	case corev1.NodeSelectorOpExists:
		return present
	case corev1.NodeSelectorOpDoesNotExist:
		return !present
	case corev1.NodeSelectorOpGt, corev1.NodeSelectorOpLt:
		return present && compareNumeric(req, value)
	default:
		return false
	}
}

func compareNumeric(req *corev1.NodeSelectorRequirement, value string) bool {
	if len(req.Values) != 1 {
		return false
	}
	have, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return false
	}
	want, err := strconv.ParseInt(req.Values[0], 10, 64)
	if err != nil {
		return false
	}
	if req.Operator == corev1.NodeSelectorOpGt {
		return have > want
	}
	return have < want
}

// taintsTolerated reports whether a daemon pod carrying these tolerations is
// admissible on a node with these taints.
func taintsTolerated(taints []corev1.Taint, tolerations []corev1.Toleration) bool {
	for i := range taints {
		taint := &taints[i]
		if taint.Effect == corev1.TaintEffectPreferNoSchedule {
			continue
		}
		if !anyTolerationTolerates(taint, tolerations) &&
			!anyTolerationTolerates(taint, daemonSetImplicitTolerations) {
			return false
		}
	}
	return true
}

func anyTolerationTolerates(taint *corev1.Taint, tolerations []corev1.Toleration) bool {
	for i := range tolerations {
		if tolerations[i].ToleratesTaint(logr.Discard(), taint, false) {
			return true
		}
	}
	return false
}
