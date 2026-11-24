package main

import (
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

// inClusterNodeName is the node an in-cluster tracer (a session Job, a spawn
// pod) runs on, from the downward-API NODE_NAME. eBPF attaches only to the
// local node's cgroups, so the dynamic target set is limited to that node's
// pods; a workstation run has no node and keeps the whole selection.
func inClusterNodeName(resolver pkgkube.PodResolverInterface) string {
	ic, ok := resolver.(interface{ InCluster() bool })
	if !ok || !ic.InCluster() {
		return ""
	}
	return strings.TrimSpace(os.Getenv("NODE_NAME"))
}

// enrichmentNamespaces are the namespaces a namespaced identity can still
// enrich peers in when it may not list cluster-wide: those the selection
// watches and those the resolved targets live in.
func enrichmentNamespaces(selection pkgkube.TargetSelection, targets []*pkgkube.PodInfo) []string {
	var out []string
	for _, ns := range selection.WatchNamespaces() {
		if ns != metav1.NamespaceAll {
			out = append(out, ns)
		}
	}
	for _, t := range targets {
		if t != nil && t.Namespace != "" {
			out = append(out, t.Namespace)
		}
	}
	return out
}
