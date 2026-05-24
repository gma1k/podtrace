package nodespawn

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func reapPod(name, host string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "ns1",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
			Labels: map[string]string{
				LabelManagedBy: ManagedByValue,
				LabelOwnerHost: host,
			},
		},
	}
}

func TestDeletePod_SwallowsNotFound(t *testing.T) {
	cs := fake.NewClientset()
	if err := DeletePod(context.Background(), cs, "ns1", "missing"); err != nil {
		t.Fatalf("DeletePod on missing pod should be a no-op, got %v", err)
	}
}

func TestDeletePod_RemovesExisting(t *testing.T) {
	cs := fake.NewClientset(reapPod("alive", "laptop", time.Minute))
	if err := DeletePod(context.Background(), cs, "ns1", "alive"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "alive", metav1.GetOptions{}); err == nil {
		t.Fatalf("expected pod to be gone")
	}
}

func TestReapStale_DeletesOnlyOldOnesMatchingHost(t *testing.T) {
	cs := fake.NewClientset(
		reapPod("fresh", "laptop", time.Minute),
		reapPod("stale-mine", "laptop", 3*time.Hour),
		reapPod("stale-other", "other-host", 3*time.Hour),
	)
	n, err := ReapStale(context.Background(), cs, "ns1", "laptop", 2*time.Hour)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 1 {
		t.Errorf("reaped = %d, want 1", n)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "stale-mine", metav1.GetOptions{}); err == nil {
		t.Errorf("stale-mine should have been deleted")
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "fresh", metav1.GetOptions{}); err != nil {
		t.Errorf("fresh should still exist: %v", err)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "stale-other", metav1.GetOptions{}); err != nil {
		t.Errorf("stale-other belongs to another host and should be untouched: %v", err)
	}
}

func TestReapStale_EmptyHostReapsAnyOwner(t *testing.T) {
	cs := fake.NewClientset(
		reapPod("stale-a", "host-a", 3*time.Hour),
		reapPod("stale-b", "host-b", 3*time.Hour),
	)
	n, err := ReapStale(context.Background(), cs, "ns1", "", time.Hour)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 2 {
		t.Errorf("reaped = %d, want 2", n)
	}
}
