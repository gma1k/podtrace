package main

import (
	"testing"

	"github.com/podtrace/podtrace/internal/kubernetes"
)

func TestBuildK8sContextMap_NamespaceFromResolvedSource(t *testing.T) {
	enriched := &kubernetes.EnrichedEvent{
		KubernetesContext: &kubernetes.KubernetesContext{
			SourceNamespace: "primary-ns",
		},
	}
	source := &kubernetes.PodInfo{PodName: "p2", Namespace: "real-ns"}

	ctx := buildK8sContextMap(enriched, source)
	if ctx["namespace"] != "real-ns" {
		t.Errorf("namespace = %v, want per-event source \"real-ns\"", ctx["namespace"])
	}
	if ctx["source_namespace"] != "real-ns" {
		t.Errorf("source_namespace = %v, want \"real-ns\"", ctx["source_namespace"])
	}
}

func TestBuildK8sContextMap_NamespaceFallsBackToEnriched(t *testing.T) {
	enriched := &kubernetes.EnrichedEvent{
		KubernetesContext: &kubernetes.KubernetesContext{
			SourceNamespace: "primary-ns",
		},
	}
	ctx := buildK8sContextMap(enriched, nil)
	if ctx["namespace"] != "primary-ns" {
		t.Errorf("namespace = %v, want fallback \"primary-ns\"", ctx["namespace"])
	}
}
