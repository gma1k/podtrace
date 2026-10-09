package inspect

import (
	"sort"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

const (
	familyEdgeRequests = "podtrace_workload_edge_requests_total"
	familyEdgeBytes    = "podtrace_workload_edge_bytes_total"
)

const unknownTargetNamespace = "unknown"

// EdgeFamilies is every family Edges reads.
func EdgeFamilies() []string {
	return []string{familyEdgeRequests, familyEdgeBytes}
}

// Edge is one workload's traffic to one Service over a window.
type Edge struct {
	Namespace       string  `json:"namespace"`
	Workload        string  `json:"workload"`
	TargetNamespace string  `json:"targetNamespace"`
	TargetService   string  `json:"targetService"`
	Requests        float64 `json:"requests"`
	Bytes           float64 `json:"bytes"`
}

// Edges returns the workload-to-Service calls that carried traffic in the
// window: decoded requests, or bytes for flows podtrace cannot decode.
func Edges(w Window) []Edge {
	if !w.Ready() {
		return nil
	}
	type key struct{ ns, workload, targetNS, target string }
	totals := map[key]*Edge{}
	add := func(family string, apply func(e *Edge, v float64)) {
		for _, d := range w.Deltas(family) {
			if d.Value <= 0 {
				continue
			}
			s := d.Sample
			targetNS, target := s.Label("target_namespace"), s.Label("target_service")
			if s.Namespace == "" || s.Workload == "" || target == "" || targetNS == "" || targetNS == unknownTargetNamespace {
				continue
			}
			k := key{s.Namespace, s.Workload, targetNS, target}
			e, ok := totals[k]
			if !ok {
				e = &Edge{Namespace: k.ns, Workload: k.workload, TargetNamespace: k.targetNS, TargetService: k.target}
				totals[k] = e
			}
			apply(e, d.Value)
		}
	}
	add(familyEdgeRequests, func(e *Edge, v float64) { e.Requests += v })
	add(familyEdgeBytes, func(e *Edge, v float64) { e.Bytes += v })

	out := make([]Edge, 0, len(totals))
	for _, e := range totals {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Namespace+"/"+a.Workload != b.Namespace+"/"+b.Workload {
			return a.Namespace+"/"+a.Workload < b.Namespace+"/"+b.Workload
		}
		return a.TargetNamespace+"/"+a.TargetService < b.TargetNamespace+"/"+b.TargetService
	})
	return out
}

// Dependencies turns edges into the lookup RootCauses takes, given how a
// Service maps to the workloads behind it. A Service no workload is known
// for contributes nothing.
func Dependencies(edges []Edge, workloadsOf func(namespace, service string) []string) func(namespace, workload string) []detector.IssueRef {
	calls := map[[2]string][]detector.IssueRef{}
	seen := map[[4]string]bool{}
	for _, e := range edges {
		for _, w := range workloadsOf(e.TargetNamespace, e.TargetService) {
			k := [4]string{e.Namespace, e.Workload, e.TargetNamespace, w}
			if seen[k] {
				continue
			}
			seen[k] = true
			from := [2]string{e.Namespace, e.Workload}
			calls[from] = append(calls[from], detector.IssueRef{Namespace: e.TargetNamespace, Workload: w})
		}
	}
	return func(namespace, workload string) []detector.IssueRef {
		return calls[[2]string{namespace, workload}]
	}
}

// localCauses links the engine's own active issues, which all come from one
// node: same-workload causes only, since the workloads a caller depends on
// may run elsewhere.
func localCauses(active map[string]detector.Issue) map[detector.IssueRef][]detector.Cause {
	refs := make([]detector.IssueRef, 0, len(active))
	for _, issue := range active {
		refs = append(refs, issue.Ref())
	}
	return detector.RootCauses(refs, nil)
}
