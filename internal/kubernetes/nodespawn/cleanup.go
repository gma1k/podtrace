package nodespawn

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultReaperMaxAge is how old a stray spawn pod has to be before the reaper
// deletes it. Tuned so a slow CLI run isn't reaped mid-execution.
const DefaultReaperMaxAge = 2 * time.Hour

// DeletePod best-effort deletes the spawn pod; NotFound is swallowed so retries
// and parallel reapers don't error out.
func DeletePod(ctx context.Context, clientset kubernetes.Interface, namespace, name string) error {
	zero := int64(0)
	err := clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{
		GracePeriodSeconds: &zero,
	})
	if err == nil || IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("nodespawn: delete %s/%s: %w", namespace, name, err)
}

// ReapStale scans the namespace for pods labelled managed-by=podtrace-cli that
// belong to ownerHost and are older than maxAge, deleting them.
func ReapStale(ctx context.Context, clientset kubernetes.Interface, namespace, ownerHost string, maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		maxAge = DefaultReaperMaxAge
	}
	labelSel := fmt.Sprintf("%s=%s", LabelManagedBy, ManagedByValue)
	if ownerHost != "" {
		labelSel += fmt.Sprintf(",%s=%s", LabelOwnerHost, sanitizeLabelValue(ownerHost))
	}
	list, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSel})
	if err != nil {
		return 0, fmt.Errorf("nodespawn: list stale pods: %w", err)
	}
	cutoff := time.Now().Add(-maxAge)
	reaped := 0
	for i := range list.Items {
		p := &list.Items[i]
		if p.CreationTimestamp.After(cutoff) {
			continue
		}
		if err := DeletePod(ctx, clientset, p.Namespace, p.Name); err == nil {
			reaped++
		}
	}
	return reaped, nil
}
