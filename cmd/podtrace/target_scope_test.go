package main

import (
	"reflect"
	"testing"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

type inClusterResolver struct {
	pkgkube.PodResolverInterface
	inCluster bool
}

func (r inClusterResolver) InCluster() bool { return r.inCluster }

func TestInClusterNodeNameScopesOnlyAnInClusterTracer(t *testing.T) {
	t.Setenv("NODE_NAME", " node-a ")
	if got := inClusterNodeName(inClusterResolver{inCluster: true}); got != "node-a" {
		t.Errorf("in-cluster node = %q, want node-a", got)
	}
	if got := inClusterNodeName(inClusterResolver{inCluster: false}); got != "" {
		t.Errorf("workstation node = %q, want none", got)
	}
	if got := inClusterNodeName(nil); got != "" {
		t.Errorf("resolver without InCluster gave node %q", got)
	}
}

func TestEnrichmentNamespacesCoverTheSelectionAndTheTargets(t *testing.T) {
	selection := pkgkube.TargetSelection{Namespaces: []string{"shop", "billing"}}
	targets := []*pkgkube.PodInfo{{Namespace: "shop"}, nil, {Namespace: "payments"}, {}}
	got := enrichmentNamespaces(selection, targets)
	want := []string{"shop", "billing", "shop", "payments"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("namespaces = %v, want %v", got, want)
	}
	if got := enrichmentNamespaces(pkgkube.TargetSelection{}, nil); len(got) != 0 {
		t.Errorf("a cluster-wide selection with no targets gave %v", got)
	}
}
