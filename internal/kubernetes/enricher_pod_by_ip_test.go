package kubernetes

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestEnrichEvent_NilEvent(t *testing.T) {
	ce := NewContextEnricher(fake.NewSimpleClientset(), &PodInfo{Namespace: "ns"})
	if got := ce.EnrichEvent(context.Background(), nil); got != nil {
		t.Errorf("expected nil for nil event, got %+v", got)
	}
}

func TestResolvePodByIP_InformerCacheHit(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "prod", Labels: map[string]string{"app": "web"}},
		Status:     corev1.PodStatus{PodIP: "10.9.9.9"},
	}
	clientset := fake.NewSimpleClientset(pod)
	ce := NewContextEnricher(clientset, &PodInfo{Namespace: "src"})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ce.Start(ctx)
	defer ce.Stop()

	ce.informerCache.mu.RLock()
	inf := ce.informerCache.podInf
	ce.informerCache.mu.RUnlock()
	if inf == nil {
		t.Skip("informer not initialized")
	}
	if err := inf.GetIndexer().Add(pod); err != nil {
		t.Fatalf("add pod to indexer: %v", err)
	}

	meta := ce.resolvePodByIP(ctx, "10.9.9.9")
	if meta == nil {
		t.Fatal("expected pod metadata from informer cache")
	}
	if meta.Name != "target" || meta.Namespace != "prod" {
		t.Errorf("unexpected metadata: %+v", meta)
	}
}

func TestFetchPodByIP_ListError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	clientset.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("synthetic list failure")
	})
	ce := NewContextEnricher(clientset, &PodInfo{})

	ce.informerCache = nil

	if meta := ce.fetchPodByIP(context.Background(), "1.2.3.4"); meta != nil {
		t.Errorf("expected nil metadata on list error, got %+v", meta)
	}
}

func TestEnrichEvent_ExternalIP(t *testing.T) {
	ce := NewContextEnricher(fake.NewSimpleClientset(), &PodInfo{Namespace: "src"})
	ce.informerCache = nil

	ev := &events.Event{Type: events.EventConnect, Target: "8.8.8.8:53"}
	enriched := ce.EnrichEvent(context.Background(), ev)
	if enriched == nil {
		t.Fatal("expected enriched event")
	}
	if !enriched.KubernetesContext.IsExternal {
		t.Errorf("expected public IP to be flagged external, got %+v", enriched.KubernetesContext)
	}
}

var _ runtime.Object = &corev1.Pod{}
