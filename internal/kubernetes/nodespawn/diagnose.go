package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	diagnoseStatusTimeout      = 5 * time.Second
	diagnoseStatusPollInterval = 250 * time.Millisecond
)

// AttachFailedError wraps an attach-time failure with the spawn pod's
// post-mortem state so the CLI can show users the actual exit reason
// (verifier rejection, missing capability, etc.) instead of the raw
// kubelet "container not found" / "CONTAINER_EXITED" race error.
type AttachFailedError struct {
	Namespace string
	PodName   string

	ExitCode *int32
	Reason   string
	Message  string
	LastLogs string

	Cause error
}

func (e *AttachFailedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.ExitCode == nil && e.LastLogs == "" {
		return fmt.Sprintf("attach to %s/%s: %v", e.Namespace, e.PodName, e.Cause)
	}
	var b strings.Builder
	if e.ExitCode != nil {
		fmt.Fprintf(&b, "spawn pod %s/%s exited with code %d before tracer was ready",
			e.Namespace, e.PodName, *e.ExitCode)
		if e.Reason != "" {
			fmt.Fprintf(&b, "\n  reason:  %s", e.Reason)
		}
		if e.Message != "" {
			fmt.Fprintf(&b, "\n  message: %s", strings.TrimRight(e.Message, "\n"))
		}
	} else {
		fmt.Fprintf(&b, "attach to %s/%s failed before pod status was finalized",
			e.Namespace, e.PodName)
		fmt.Fprintf(&b, "\n  attach error: %v", e.Cause)
	}
	if e.LastLogs != "" {
		fmt.Fprintf(&b, "\n  last logs:\n%s", indent(e.LastLogs, "    "))
	}
	fmt.Fprintf(&b, "\n  to reproduce: kubectl -n %s logs %s", e.Namespace, e.PodName)
	return b.String()
}

func (e *AttachFailedError) Unwrap() error { return e.Cause }

// diagnoseAttachFailure refreshes the spawn pod's status after an attach error
// and, if the primary container has already terminated, returns a structured
// AttachFailedError carrying its exit code, reason, termination message, and
// last log lines.
func diagnoseAttachFailure(
	ctx context.Context,
	clientset kubernetes.Interface,
	namespace, podName string,
	origErr error,
) error {
	if origErr == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return origErr
	}
	if errors.Is(origErr, context.Canceled) {
		return origErr
	}

	term, logs, podGone := waitForTerminalSignals(ctx, clientset, namespace, podName)
	if errors.Is(ctx.Err(), context.Canceled) {
		return origErr
	}

	if podGone {
		return fmt.Errorf("spawn pod %s/%s no longer exists (deleted or evicted during attach): %w",
			namespace, podName, origErr)
	}

	if term == nil && logs == "" {
		return origErr
	}

	afe := &AttachFailedError{
		Namespace: namespace,
		PodName:   podName,
		LastLogs:  logs,
		Cause:     origErr,
	}
	if term != nil {
		exit := term.ExitCode
		afe.ExitCode = &exit
		afe.Reason = term.Reason
		afe.Message = term.Message
	}
	return afe
}

// waitForTerminalSignals polls the apiserver until the primary container's
// terminal state appears, AND accumulates the best-available pod logs along
// the way. Returns:
//   - term: the structured terminal state if observed, else nil
//   - logs: the latest non-empty log dump seen across all poll iterations
//   - podGone: true iff the apiserver definitively reports the pod is gone
//     (NotFound), so callers can short-circuit instead of burning the budget
func waitForTerminalSignals(
	ctx context.Context,
	clientset kubernetes.Interface,
	namespace, podName string,
) (term *corev1.ContainerStateTerminated, logs string, podGone bool) {
	deadline := time.Now().Add(diagnoseStatusTimeout)
	for {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, logs, false
		}
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return nil, logs, true
		case err == nil && pod != nil:
			if cs := primaryContainerStatus(pod); cs != nil && cs.State.Terminated != nil {
				if logs == "" {
					logs = dumpPodLogs(ctx, clientset, namespace, podName)
				}
				return cs.State.Terminated, logs, false
			}
		}
		if logs == "" {
			logs = dumpPodLogs(ctx, clientset, namespace, podName)
		}
		if time.Now().After(deadline) {
			return nil, logs, false
		}
		select {
		case <-ctx.Done():
			return nil, logs, false
		case <-time.After(diagnoseStatusPollInterval):
		}
	}
}

// primaryContainerStatus returns the status entry for the spawn pod's only
// container ("podtrace" — see pod_spec.go).
func primaryContainerStatus(pod *corev1.Pod) *corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	for i, cs := range pod.Status.ContainerStatuses {
		if cs.Name == "podtrace" {
			return &pod.Status.ContainerStatuses[i]
		}
	}
	if len(pod.Status.ContainerStatuses) > 0 {
		return &pod.Status.ContainerStatuses[0]
	}
	return nil
}

func indent(s, prefix string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}