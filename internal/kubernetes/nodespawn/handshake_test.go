package nodespawn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func attachReview(cs *fake.Clientset, allowed bool, err error) *[]string {
	var asked []string
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r := a.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		ra := r.Spec.ResourceAttributes
		asked = append(asked, ra.Namespace+"/"+ra.Verb+"/"+ra.Resource+"/"+ra.Subresource)
		if err != nil {
			return true, nil, err
		}
		r.Status.Allowed = allowed
		return true, r, nil
	})
	return &asked
}

func TestCanAttach(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed bool
		err     error
		want    bool
	}{
		{"allowed", true, nil, true},
		{"denied streams logs instead", false, nil, false},
		{"review failure assumes allowed", false, errors.New("apiserver down"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset()
			asked := attachReview(cs, tc.allowed, tc.err)
			if got := CanAttach(context.Background(), cs, "podtrace-cli"); got != tc.want {
				t.Fatalf("CanAttach = %v, want %v", got, tc.want)
			}
			if len(*asked) != 1 || (*asked)[0] != "podtrace-cli/create/pods/attach" {
				t.Fatalf("reviewed %v, want podtrace-cli/create/pods/attach", *asked)
			}
		})
	}
}

func TestWithHandshake(t *testing.T) {
	got, _ := io.ReadAll(withHandshake(nil))
	if string(got) != "\n" {
		t.Errorf("multi-node stdin = %q, want only the handshake", got)
	}
	got, _ = io.ReadAll(withHandshake(strings.NewReader("typed")))
	if string(got) != "\ntyped" {
		t.Errorf("single-node stdin = %q, want the handshake then the terminal", got)
	}
}

func TestAwaitAttachHandshake(t *testing.T) {
	if !AwaitAttachHandshake(strings.NewReader("\n"), time.Second) {
		t.Error("a handshake byte must release the child")
	}
	if !AwaitAttachHandshake(strings.NewReader(""), time.Second) {
		t.Error("a closed stdin must release the child")
	}
	r, w := io.Pipe()
	defer func() { _ = w.Close() }()
	start := time.Now()
	if AwaitAttachHandshake(r, 20*time.Millisecond) {
		t.Error("no handshake must report a timeout")
	}
	if time.Since(start) > time.Second {
		t.Error("the wait is not bounded by its timeout")
	}
}

func TestBuildPodSpecSetsTheHandshakeOnlyWhenAsked(t *testing.T) {
	opts := baseOpts()
	without, err := BuildPodSpec(opts)
	if err != nil {
		t.Fatal(err)
	}
	if podWaitsForAttach(without) {
		t.Error("a pod built without AttachHandshake must not wait")
	}
	opts.AttachHandshake = true
	with, err := BuildPodSpec(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !podWaitsForAttach(with) {
		t.Errorf("env %v lacks %s=1", with.Spec.Containers[0].Env, EnvAttachHandshake)
	}
}

func captureAttachStdin(t *testing.T, cs *fake.Clientset) *[]string {
	t.Helper()
	var stdins []string
	var mu sync.Mutex
	orig := attachToPod
	attachToPod = func(ctx context.Context, _ *rest.Config, c kubernetes.Interface, pod *corev1.Pod, streams genericiooptions.IOStreams) (bool, error) {
		got := "<nil>"
		if streams.In != nil {
			b, _ := io.ReadAll(streams.In)
			got = string(b)
		}
		mu.Lock()
		stdins = append(stdins, got)
		mu.Unlock()
		p, err := c.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "podtrace", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}}}
		_, err = c.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, p, metav1.UpdateOptions{})
		return false, err
	}
	t.Cleanup(func() { attachToPod = orig })
	return &stdins
}

func handshakePodSpec(t *testing.T) *corev1.Pod {
	t.Helper()
	opts := baseOpts()
	opts.Namespace = "ns1"
	opts.AttachHandshake = true
	spec, err := BuildPodSpec(opts)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestTheAttachSendsTheHandshakeBeforeTheTerminal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		multiNode bool
		handshake bool
		want      string
	}{
		{"single node", false, true, "\ntyped"},
		{"multi node", true, true, "\n"},
		{"single node without handshake", false, false, "typed"},
		{"multi node without handshake", true, false, "<nil>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useClassicListWatch(t)
			cs := fake.NewClientset()
			runningOnCreate(cs)
			stdins := captureAttachStdin(t, cs)
			spec := spawnPodSpec(t, "ns1")
			if tc.handshake {
				spec = handshakePodSpec(t)
			}
			var wmu sync.Mutex
			err := runOneNode(context.Background(), RunOptions{
				Clientset:  cs,
				RestConfig: &rest.Config{},
				Streams:    genericiooptions.IOStreams{In: strings.NewReader("typed"), Out: &bytes.Buffer{}, ErrOut: io.Discard},
			}, spec, tc.multiNode, &wmu, "")
			if err != nil {
				t.Fatalf("runOneNode: %v", err)
			}
			if len(*stdins) != 1 || (*stdins)[0] != tc.want {
				t.Fatalf("attach stdin = %q, want %q", *stdins, tc.want)
			}
		})
	}
}

func TestRunAsksForTheHandshakeOnlyWhenAttachIsAllowed(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		cs := fake.NewClientset(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "api", UID: "u1"},
			Spec:       corev1.PodSpec{NodeName: "node-1"},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app", ContainerID: "containerd://abc",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}}},
		})
		attachReview(cs, allowed, nil)
		var created *corev1.Pod
		cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
			created = a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
			return true, nil, errors.New("stop here")
		})
		_ = Run(context.Background(), RunOptions{
			Clientset:      cs,
			RestConfig:     &rest.Config{},
			Image:          "x",
			BuildChildArgs: func(string, []PodRef) []string { return []string{"--noop"} },
			Selection:      pkgkube.TargetSelection{DefaultNamespace: "tenant-a", Pods: []string{"api"}},
		})
		if created == nil {
			t.Fatal("no spawn pod was created")
		}
		if got := podWaitsForAttach(created); got != allowed {
			t.Errorf("attach allowed=%v: pod waits for the handshake = %v", allowed, got)
		}
	}
}
