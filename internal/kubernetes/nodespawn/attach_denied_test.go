package nodespawn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestAttachForbidden(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{apierrors.NewForbidden(schema.GroupResource{Resource: "pods/attach"}, "p", errors.New("rbac")), true},
		{errors.New(`unable to upgrade connection: pods "p" is forbidden: User "u" cannot create resource "pods/attach" in API group ""`), true},
		{fmt.Errorf("attach: %w", errors.New("unable to upgrade connection: Forbidden")), true},
		{errors.New("unable to upgrade connection: container not found"), false},
		{errors.New("connection reset by peer"), false},
	}
	for _, tc := range cases {
		if got := attachForbidden(tc.err); got != tc.want {
			t.Errorf("attachForbidden(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func finishPodOnStream(t *testing.T, cs kubernetes.Interface, pod *corev1.Pod) {
	t.Helper()
	p, err := cs.CoreV1().Pods(pod.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "podtrace", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}}}
	if _, err := cs.CoreV1().Pods(pod.Namespace).UpdateStatus(context.Background(), p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestADeniedAttachStreamsThePodLogFromItsStartAndSaysSo(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	origAttach, origLogs := attachToPod, streamLogsFromStart
	t.Cleanup(func() { attachToPod, streamLogsFromStart = origAttach, origLogs })
	attachToPod = func(context.Context, *rest.Config, kubernetes.Interface, *corev1.Pod, genericiooptions.IOStreams) (bool, error) {
		t.Error("an attach known to be denied must not be tried")
		return false, nil
	}
	var logged bool
	streamLogsFromStart = func(_ context.Context, c kubernetes.Interface, pod *corev1.Pod, streams genericiooptions.IOStreams) error {
		logged = true
		if streams.In != nil {
			t.Error("the pod-log stream has no stdin to forward")
		}
		_, _ = io.WriteString(streams.Out, "Resolved target pod\n")
		finishPodOnStream(t, c, pod)
		return nil
	}

	var out, errOut bytes.Buffer
	var wmu sync.Mutex
	err := runOneNode(context.Background(), RunOptions{
		Clientset:    cs,
		RestConfig:   &rest.Config{},
		Streams:      genericiooptions.IOStreams{Out: &out, ErrOut: &errOut},
		attachDenied: true,
	}, spawnPodSpec(t, "ns1"), false, &wmu, "")
	if err != nil {
		t.Fatalf("runOneNode: %v", err)
	}
	if !logged || !strings.Contains(out.String(), "Resolved target pod") {
		t.Fatalf("pod log not streamed: logged=%v out=%q", logged, out.String())
	}
	if !strings.Contains(errOut.String(), "pods/attach is not allowed") {
		t.Fatalf("no degraded-mode warning: %q", errOut.String())
	}
}

func TestAnAttachThatFallsBackToTheLogWarns(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	orig := attachToPod
	t.Cleanup(func() { attachToPod = orig })
	attachToPod = func(_ context.Context, _ *rest.Config, c kubernetes.Interface, pod *corev1.Pod, _ genericiooptions.IOStreams) (bool, error) {
		finishPodOnStream(t, c, pod)
		return true, nil
	}
	var errOut bytes.Buffer
	var wmu sync.Mutex
	if err := runOneNode(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: io.Discard, ErrOut: &errOut},
	}, spawnPodSpec(t, "ns1"), false, &wmu, ""); err != nil {
		t.Fatalf("runOneNode: %v", err)
	}
	if !strings.Contains(errOut.String(), "pods/attach is not allowed") {
		t.Fatalf("no degraded-mode warning: %q", errOut.String())
	}
}

func TestStreamLogsFromStartCopiesThePodLog(t *testing.T) {
	cs := fake.NewClientset()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "p"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "podtrace"}}}}
	var out bytes.Buffer
	if err := streamLogsFromStart(context.Background(), cs, pod, genericiooptions.IOStreams{Out: &out}); err != nil {
		t.Fatalf("streamLogsFromStart: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("nothing copied from the pod log")
	}
}
