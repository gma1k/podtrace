package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
	if e.ExitCode == nil {
		return fmt.Sprintf("attach to %s/%s: %v", e.Namespace, e.PodName, e.Cause)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "spawn pod %s/%s exited with code %d before tracer was ready",
		e.Namespace, e.PodName, *e.ExitCode)
	if e.Reason != "" {
		fmt.Fprintf(&b, "\n  reason:  %s", e.Reason)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, "\n  message: %s", strings.TrimRight(e.Message, "\n"))
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

	pod, getErr := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if getErr != nil || pod == nil {
		return origErr
	}

	cs := primaryContainerStatus(pod)
	if cs == nil || cs.State.Terminated == nil {
		return origErr
	}

	term := cs.State.Terminated
	logs := dumpPodLogs(ctx, clientset, namespace, podName)

	exit := term.ExitCode
	return &AttachFailedError{
		Namespace: namespace,
		PodName:   podName,
		ExitCode:  &exit,
		Reason:    term.Reason,
		Message:   term.Message,
		LastLogs:  logs,
		Cause:     origErr,
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