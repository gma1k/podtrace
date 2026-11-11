package main

import (
	"reflect"
	"runtime"
	"strconv"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/safeconv"
)

func freshInterner(t *testing.T) {
	t.Helper()
	orig := k8sContexts
	k8sContexts = &contextInterner{}
	t.Cleanup(func() { k8sContexts = orig })
}

func samePointer(a, b map[string]interface{}) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

func enrichedToPeer(labels map[string]string) *kubernetes.EnrichedEvent {
	return &kubernetes.EnrichedEvent{KubernetesContext: &kubernetes.KubernetesContext{
		SourceNamespace: "shop", TargetPodName: "db-0", TargetNamespace: "shop", TargetLabels: labels,
	}}
}

func TestEventsToTheSamePeerShareOneContext(t *testing.T) {
	freshInterner(t)
	labels := map[string]string{"app": "db"}
	source := &kubernetes.PodInfo{PodName: "api", Namespace: "shop", Labels: map[string]string{"app": "api"}}
	a := buildK8sContextMap(enrichedToPeer(labels), source)
	b := buildK8sContextMap(enrichedToPeer(labels), source)
	if !samePointer(a, b) {
		t.Error("two events to the same peer from the same source got separate context maps")
	}
	if a["target_pod"] != "db-0" || a["source_pod"] != "api" {
		t.Errorf("context = %v", a)
	}
}

func TestADifferentPeerSourceOrLabelSetGetsItsOwnContext(t *testing.T) {
	freshInterner(t)
	labels := map[string]string{"app": "db"}
	source := &kubernetes.PodInfo{PodName: "api", Namespace: "shop"}
	base := buildK8sContextMap(enrichedToPeer(labels), source)
	other := enrichedToPeer(labels)
	other.KubernetesContext.TargetPodName = "db-1"
	refreshed := map[string]string{"app": "db"}
	for name, ctx := range map[string]map[string]interface{}{
		"another peer":       buildK8sContextMap(other, source),
		"another source":     buildK8sContextMap(enrichedToPeer(labels), &kubernetes.PodInfo{PodName: "web", Namespace: "shop"}),
		"no source":          buildK8sContextMap(enrichedToPeer(labels), nil),
		"refreshed pod info": buildK8sContextMap(enrichedToPeer(refreshed), source),
	} {
		if samePointer(base, ctx) {
			t.Errorf("%s shared a context it does not match", name)
		}
	}
}

func TestTheInternerStopsSharingPastItsBound(t *testing.T) {
	in := &contextInterner{}
	for i := 0; i < maxInternedContexts+10; i++ {
		key := contextKey{targetPod: strconv.Itoa(i)}
		if m := in.context(key, func() map[string]interface{} { return map[string]interface{}{"i": i} }); m["i"] != i {
			t.Fatalf("context %d = %v", i, m)
		}
	}
	if len(in.contexts) != maxInternedContexts {
		t.Errorf("held %d contexts, want the bound %d", len(in.contexts), maxInternedContexts)
	}
	for i := 0; i < maxInternedContexts+10; i++ {
		in.podMetadata("ns", strconv.Itoa(i), "c")
	}
	if len(in.metadata) != maxInternedContexts {
		t.Errorf("held %d pod identities, want the bound %d", len(in.metadata), maxInternedContexts)
	}
}

func TestEventsFromOnePodShareItsMetadata(t *testing.T) {
	freshInterner(t)
	resolve := func(*events.Event) *kubernetes.PodInfo {
		return &kubernetes.PodInfo{PodName: "api", Namespace: "shop", ContainerName: "app"}
	}
	a, b := &events.Event{}, &events.Event{}
	attachSourcePod(a, resolve)
	attachSourcePod(b, resolve)
	if a.K8s == nil || a.K8s != b.K8s || a.K8s.PodName != "api" || a.K8s.ContainerName != "app" {
		t.Errorf("metadata = %+v and %+v, want one shared api/app identity", a.K8s, b.K8s)
	}
}

func TestManyEventsToOnePeerRetainOneContext(t *testing.T) {
	freshInterner(t)
	labels := map[string]string{"app": "db"}
	source := &kubernetes.PodInfo{PodName: "api", Namespace: "shop", Labels: map[string]string{"app": "api"}}
	const n = 100_000
	kept := make([]map[string]interface{}, n)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range kept {
		kept[i] = buildK8sContextMap(enrichedToPeer(labels), source)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	perEvent := (safeconv.Uint64ToInt64(after.HeapAlloc) - safeconv.Uint64ToInt64(before.HeapAlloc)) / n
	if perEvent > 32 {
		t.Errorf("each event retained %d bytes of context, want only its reference to the shared map", perEvent)
	}
	runtime.KeepAlive(kept)
}
