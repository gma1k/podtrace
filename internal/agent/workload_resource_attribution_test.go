package agent

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/gma1k/podtrace/internal/events"
)

func replicaMeta(pod, uid, container string) *events.K8sMetadata {
	return &events.K8sMetadata{
		Namespace:     "shop",
		WorkloadName:  "checkout",
		WorkloadKind:  "Deployment",
		NodeName:      "node-a",
		PodName:       pod,
		PodUID:        uid,
		ContainerName: container,
	}
}

func TestWorkloadResourceDoesNotFreezeTheFirstPod(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	w := newTestProviders(t, rec, nil)

	for _, m := range []*events.K8sMetadata{
		replicaMeta("checkout-aaa", "uid-aaa", "istio-proxy"),
		replicaMeta("checkout-bbb", "uid-bbb", "app"),
	} {
		_, span := w.tracerFor(m).Start(context.Background(), "event")
		span.End()
	}

	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("recorded %d spans, want 2", len(spans))
	}
	if spans[0].Resource() != spans[1].Resource() {
		t.Fatal("two replicas of one workload got different Resources; the provider cache is not shared")
	}
	attrs := map[string]string{}
	for _, kv := range spans[1].Resource().Attributes() {
		attrs[string(kv.Key)] = kv.Value.String()
	}
	for _, key := range []string{"k8s.pod.name", "k8s.pod.uid", "k8s.container.name"} {
		if v, ok := attrs[key]; ok {
			t.Errorf("Resource carries %s=%q from the first pod seen, so every replica is attributed to it", key, v)
		}
	}
	want := map[string]string{
		"service.name":        "checkout",
		"service.namespace":   "shop",
		"k8s.namespace.name":  "shop",
		"k8s.node.name":       "node-a",
		"k8s.deployment.name": "checkout",
		"podtrace.cr.name":    "cr",
	}
	for key, value := range want {
		if attrs[key] != value {
			t.Errorf("Resource %s = %q, want %q", key, attrs[key], value)
		}
	}
}

func TestWorkloadResourceOmitsEmptyNamespaceAndNode(t *testing.T) {
	w := newTestProviders(t, tracetest.NewSpanRecorder(), nil)
	res := w.resourceFor(&events.K8sMetadata{WorkloadName: "checkout", WorkloadKind: "StatefulSet"})
	for _, kv := range res.Attributes() {
		switch string(kv.Key) {
		case "service.namespace", "k8s.namespace.name", "k8s.node.name":
			t.Errorf("Resource carries empty %s", kv.Key)
		}
	}
	if v, ok := res.Set().Value("k8s.statefulset.name"); !ok || v.AsString() != "checkout" {
		t.Errorf("k8s.statefulset.name = %v, want checkout", v.String())
	}
}
