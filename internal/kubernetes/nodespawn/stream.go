package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/remotecommand"
	watchtools "k8s.io/client-go/tools/watch"
)

func waitForPodRunningOrTerminated(ctx context.Context, clientset kubernetes.Interface, namespace, name string) (*corev1.Pod, error) {
	fieldSel := fields.OneTermEqualSelector("metadata.name", name).String()
	lw := &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = fieldSel
			return clientset.CoreV1().Pods(namespace).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = fieldSel
			return clientset.CoreV1().Pods(namespace).Watch(ctx, opts)
		},
	}

	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	evt, err := watchtools.UntilWithSync(waitCtx, lw, &corev1.Pod{}, nil, func(e watch.Event) (bool, error) {
		switch e.Type {
		case watch.Deleted:
			return false, fmt.Errorf("spawn pod %s/%s deleted before reaching Running", namespace, name)
		case watch.Error:
			return false, fmt.Errorf("watch error on %s/%s", namespace, name)
		}
		p, ok := e.Object.(*corev1.Pod)
		if !ok {
			return false, nil
		}
		switch p.Status.Phase {
		case corev1.PodRunning, corev1.PodSucceeded, corev1.PodFailed:
			return true, nil
		case corev1.PodPending:
			if r := unschedulableReason(p); r != "" {
				return false, fmt.Errorf("spawn pod %s/%s cannot be scheduled: %s", namespace, name, r)
			}
			if r := imagePullFailureReason(p); r != "" {
				return false, fmt.Errorf("spawn pod %s/%s image pull failed: %s", namespace, name, r)
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	pod, _ := evt.Object.(*corev1.Pod)
	return pod, nil
}

func unschedulableReason(p *corev1.Pod) string {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
			return c.Message
		}
	}
	return ""
}

func imagePullFailureReason(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil {
			switch w.Reason {
			case "ImagePullBackOff", "ErrImagePull", "InvalidImageName":
				return w.Reason + ": " + w.Message
			}
		}
	}
	return ""
}

// AttachToPod attaches stdin/stdout/stderr to the spawn pod and blocks until
// the pod terminates or ctx is cancelled.
func AttachToPod(ctx context.Context, restCfg *rest.Config, clientset kubernetes.Interface, pod *corev1.Pod, streams genericiooptions.IOStreams) (warnDegraded bool, err error) {
	if pod == nil {
		return false, fmt.Errorf("nodespawn: nil pod")
	}
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(pod.Namespace).Name(pod.Name).
		SubResource("attach").
		VersionedParams(&corev1.PodAttachOptions{
			Container: pod.Spec.Containers[0].Name,
			Stdin:     streams.In != nil,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, execErr := remotecommand.NewSPDYExecutor(restCfg, "POST", req.URL())
	if execErr == nil {
		opts := remotecommand.StreamOptions{Stdout: streams.Out, Stderr: streams.ErrOut}
		if streams.In != nil {
			opts.Stdin = streams.In
		}
		streamErr := exec.StreamWithContext(ctx, opts)
		if streamErr == nil {
			return false, nil
		}
		if !apierrors.IsForbidden(streamErr) {
			return false, streamErr
		}
	}

	return true, streamLogs(ctx, clientset, pod, streams.Out)
}

func streamLogs(ctx context.Context, clientset kubernetes.Interface, pod *corev1.Pod, stdout io.Writer) error {
	req := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		Container: pod.Spec.Containers[0].Name,
		Follow:    true,
	})
	rc, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("nodespawn: stream logs: %w", err)
	}
	defer func() { _ = rc.Close() }()
	_, copyErr := io.Copy(stdout, rc)
	if copyErr != nil && !errors.Is(copyErr, context.Canceled) {
		return copyErr
	}
	return nil
}

// WaitForExitCode polls until the primary container terminates and returns its
// exit code.
func WaitForExitCode(ctx context.Context, clientset kubernetes.Interface, namespace, name string) int32 {
	const pollEvery = 500 * time.Millisecond
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return -1
		default:
		}
		p, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return -1
		}
		for _, cs := range p.Status.ContainerStatuses {
			if t := cs.State.Terminated; t != nil {
				return t.ExitCode
			}
		}
		time.Sleep(pollEvery)
	}
	return -1
}

// IsNotFound is exported so cleanup callers can swallow "already-gone" errors.
func IsNotFound(err error) bool { return apierrors.IsNotFound(err) }
