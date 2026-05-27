package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/podtrace/podtrace/internal/logger"
)

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

// ReapStale deletes spawn pods whose owning CLI process is gone.
func ReapStale(ctx context.Context, clientset kubernetes.Interface, namespace, ownerHost string) (int, error) {
	return reapStaleWithLiveness(ctx, clientset, namespace, ownerHost, processAlive)
}

// reapStaleWithLiveness is the test-injectable form. Production callers use
// ReapStale, which wires in the OS-backed processAlive check.
func reapStaleWithLiveness(
	ctx context.Context,
	clientset kubernetes.Interface,
	namespace, ownerHost string,
	alive func(int) bool,
) (int, error) {
	labelSel := fmt.Sprintf("%s=%s", LabelManagedBy, ManagedByValue)
	if ownerHost != "" {
		labelSel += fmt.Sprintf(",%s=%s", LabelOwnerHost, sanitizeLabelValue(ownerHost))
	}
	list, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSel})
	if err != nil {
		return 0, fmt.Errorf("nodespawn: list stale pods: %w", err)
	}

	reaped := 0
	for i := range list.Items {
		p := &list.Items[i]

		pidStr := p.Labels[LabelOwnerPID]
		if pidStr == "" {
			logger.Debug("Spawn pod has no owner-pid label; not reaping (anomaly — surface but don't touch)",
				zap.String("namespace", p.Namespace),
				zap.String("name", p.Name))
			continue
		}
		pid, perr := strconv.Atoi(pidStr)
		if perr != nil || pid <= 0 {
			logger.Debug("Spawn pod has malformed owner-pid label; not reaping",
				zap.String("namespace", p.Namespace),
				zap.String("name", p.Name),
				zap.String("owner-pid", pidStr))
			continue
		}
		if alive(pid) {
			// owning CLI is still running — leave its pod alone.
			continue
		}

		// dead owner → orphan → reap
		if derr := DeletePod(ctx, clientset, p.Namespace, p.Name); derr == nil {
			reaped++
			logger.Debug("Reaped orphan spawn pod",
				zap.String("namespace", p.Namespace),
				zap.String("name", p.Name),
				zap.Int("owner_pid", pid))
		}
	}
	return reaped, nil
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
		return false
	}
	return true
}