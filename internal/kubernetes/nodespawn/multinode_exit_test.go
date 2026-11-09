package nodespawn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestAMultiNodeSpawnTagsOutputAndExitWithTheTargetNode(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	orig := attachToPod
	attachToPod = func(ctx context.Context, _ *rest.Config, c kubernetes.Interface, pod *corev1.Pod, streams genericiooptions.IOStreams) (bool, error) {
		_, _ = io.WriteString(streams.Out, "live event\n")
		p, err := c.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  "podtrace",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 3}},
		}}
		_, err = c.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, p, metav1.UpdateOptions{})
		return false, err
	}
	t.Cleanup(func() { attachToPod = orig })

	var out bytes.Buffer
	var wmu sync.Mutex
	err := runOneNode(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: &out, ErrOut: io.Discard},
	}, spawnPodSpec(t, "ns1"), true, &wmu, "shop/api")

	if !strings.Contains(out.String(), "[node-1: shop/api] live event") {
		t.Errorf("output %q is not tagged with the node and targets", out.String())
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 3 || exitErr.Node != "node-1" {
		t.Fatalf("err = %v, want exit code 3 on node-1", err)
	}
}
