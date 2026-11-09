package kubernetes

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestUpsertOfAnUnrelatedPodPublishesNothing(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Pods: []string{"ns-a/pod-1"}})
	other := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "busy-neighbour", UID: types.UID("u-other")}}
	if tr.upsertPod(context.Background(), other) {
		t.Fatal("an update of a pod that was never a target must not publish a snapshot")
	}
}

func TestATargetThatStopsMatchingIsPublished(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Pods: []string{"ns-a/pod-1"}})
	uid := types.UID("u-1")
	tr.mu.Lock()
	tr.targets[uid] = &PodInfo{Namespace: "ns-a", PodName: "pod-1"}
	tr.mu.Unlock()
	renamed := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns-b", Name: "pod-1", UID: uid}}
	if !tr.upsertPod(context.Background(), renamed) {
		t.Fatal("dropping a former target must publish a snapshot")
	}
	tr.mu.Lock()
	_, still := tr.targets[uid]
	tr.mu.Unlock()
	if still {
		t.Fatal("the former target is still in the set")
	}
}
