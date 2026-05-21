package agent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// TestEnricher_FullPipeline drives Reconcile → enricher.Snapshot →
// Router.Export to exporter receives ev.K8s.
func TestEnricher_FullPipeline(t *testing.T) {
	const node, sysNS, ns = "n-1", "podtrace-system", "default"
	uid := types.UID("uid-enrich")
	tcontroller := true

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-7d8c9c-abcde", Namespace: ns, UID: "pod-uid-1",
			Labels: map[string]string{"app": "web"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-7d8c9c", Controller: &tcontroller},
			},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"},
	}
	cm := makeBundleCM(sysNS, uid, "1")

	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(pt, pod, cm).Build()

	const cgID uint64 = 4242
	exp := &fakeExporter{name: "fx"}
	enricher := NewPodEnricher()

	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: sysNS,
		Router:          NewRouter(nil).WithEnricher(enricher),
		Metrics:         NewMetrics(),
		TargetsCh:       make(chan tracer.TargetSet, 4),
		Enricher:        enricher,
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return exp, nil
		},
		CgroupResolver: func(pods []*corev1.Pod) (map[uint64]struct{}, error) {
			out := map[uint64]struct{}{}
			for range pods {
				out[cgID] = struct{}{}
			}
			return out, nil
		},
		PodAttributor: func(pods []*corev1.Pod) []PodCgroupEntry {
			out := make([]PodCgroupEntry, 0, len(pods))
			for _, p := range pods {
				out = append(out, PodCgroupEntry{
					CgroupID:      cgID,
					Pod:           p,
					ContainerName: "app",
					ContainerID:   "containerd://deadbeef",
				})
			}
			return out
		},
		exporterCache: map[CRKey]cachedExporter{},
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	meta, ok := enricher.Lookup(cgID)
	if !ok {
		t.Fatal("enricher cache miss for known cgroup")
	}
	want := events.K8sMetadata{
		Namespace:     ns,
		PodName:       "web-7d8c9c-abcde",
		PodUID:        "pod-uid-1",
		NodeName:      node,
		ContainerName: "app",
		WorkloadKind:  "Deployment",
		WorkloadName:  "web",
	}
	if meta != want {
		t.Errorf("enricher meta = %+v, want %+v", meta, want)
	}

	captured := &capturingExporter{}
	r.Router.Publish([]CRRule{{
		Key:       CRKey{Namespace: ns, Name: "pt"},
		CgroupIDs: map[uint64]struct{}{cgID: {}},
		Filters:   map[events.EventType]struct{}{events.EventDNS: {}},
		Exporter:  captured,
	}})

	batch := []*events.Event{
		{CgroupID: cgID, Type: events.EventDNS, Target: "example.com"},
		{CgroupID: cgID, Type: events.EventDNS, Target: "example.org"},
		{CgroupID: 99, Type: events.EventDNS}, // miss; not routed
	}
	if err := r.Router.Export(context.Background(), batch); err != nil {
		t.Fatalf("Router.Export: %v", err)
	}

	got := captured.Snapshot()
	if len(got) != 2 {
		t.Fatalf("exporter received %d events, want 2", len(got))
	}
	for i, ev := range got {
		if ev.K8s == nil {
			t.Errorf("event %d: K8s pointer is nil", i)
			continue
		}
		if *ev.K8s != want {
			t.Errorf("event %d: K8s = %+v, want %+v", i, *ev.K8s, want)
		}
	}
	if got[0].K8s != got[1].K8s {
		t.Error("two events with the same cgroup must share the K8s pointer")
	}

	stats := enricher.Stats()
	if stats.Hits < 1 {
		t.Errorf("expected >=1 enricher hit, got %d", stats.Hits)
	}
	if stats.Misses < 1 {
		t.Errorf("expected >=1 enricher miss, got %d", stats.Misses)
	}
	if stats.OwnerResolved != 1 {
		t.Errorf("OwnerResolved = %d, want 1", stats.OwnerResolved)
	}
}

// capturingExporter records every event it sees so the integration
// test can assert on ev.K8s after the router runs.
type capturingExporter struct {
	events []*events.Event
}

func (e *capturingExporter) Name() string { return "capture" }
func (e *capturingExporter) Export(_ context.Context, batch []*events.Event) error {
	e.events = append(e.events, batch...)
	return nil
}
func (e *capturingExporter) Close(_ context.Context) error { return nil }
func (e *capturingExporter) Snapshot() []*events.Event {
	out := make([]*events.Event, len(e.events))
	copy(out, e.events)
	return out
}

// TestEnricher_TargetSetPopulatesOwner verifies the second
// improvement: buildTargetSet now populates OwnerKind / OwnerName /
// ContainerName fields on tracer.Target objects (previously left
// zero), so the tracer engine can attach to containers with stable
// identity attributes available downstream.
func TestEnricher_TargetSetPopulatesOwner(t *testing.T) {
	tcontroller := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-7d8c9c-x", Namespace: "ns", UID: "pod-uid",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-7d8c9c", Controller: &tcontroller},
			},
		},
		Spec:   corev1.PodSpec{NodeName: "n"},
		Status: corev1.PodStatus{PodIP: "10.0.0.2"},
	}
	rules := []CRRule{{CgroupIDs: map[uint64]struct{}{1: {}}}}
	entries := []PodCgroupEntry{
		{CgroupID: 1, Pod: pod, ContainerName: "app", ContainerID: "abc",
			CgroupPath: "/sys/fs/cgroup/x"},
	}
	out := buildTargetSet(rules, []*corev1.Pod{pod}, entries)
	if len(out) != 1 {
		t.Fatalf("want 1 target, got %d", len(out))
	}
	tgt := out[0]
	if tgt.OwnerKind != "Deployment" || tgt.OwnerName != "web" {
		t.Errorf("OwnerKind/Name = %q/%q, want Deployment/web", tgt.OwnerKind, tgt.OwnerName)
	}
	if tgt.ContainerName != "app" || tgt.ContainerID != "abc" {
		t.Errorf("Container fields wrong: %+v", tgt)
	}
	if tgt.PodIP != "10.0.0.2" {
		t.Errorf("PodIP = %q, want 10.0.0.2", tgt.PodIP)
	}
}