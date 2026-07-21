package nodespawn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

type restClientClientset struct {
	*fake.Clientset
	rc rest.Interface
}

func (c *restClientClientset) CoreV1() corev1client.CoreV1Interface {
	return &restClientCoreV1{c.Clientset.CoreV1(), c.rc}
}

type restClientCoreV1 struct {
	corev1client.CoreV1Interface
	rc rest.Interface
}

func (c *restClientCoreV1) RESTClient() rest.Interface { return c.rc }

func newAttachClientset(t *testing.T, objs ...runtime.Object) (*restClientClientset, *rest.Config) {
	t.Helper()
	f := fake.NewClientset(objs...)
	cfg := &rest.Config{
		Host: "https://127.0.0.1:1",
		ContentConfig: rest.ContentConfig{
			GroupVersion:         &corev1.SchemeGroupVersion,
			NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		},
	}
	rc, err := rest.RESTClientFor(cfg)
	if err != nil {
		t.Fatalf("RESTClientFor: %v", err)
	}
	return &restClientClientset{f, rc}, cfg
}

func TestAttachToPod_StreamErrorReturned(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "podtrace"}}},
	}
	cs, cfg := newAttachClientset(t, pod)

	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	warn, err := AttachToPod(ctx, cfg, cs, pod, genericiooptions.IOStreams{Out: out, ErrOut: errOut})
	if err == nil {
		t.Fatalf("expected a stream error when the apiserver is unreachable")
	}
	if warn {
		t.Errorf("a non-forbidden stream error must not request the degraded (log-follow) fallback")
	}
	if !strings.Contains(err.Error(), "connection refused") && !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("unexpected error, want a dial failure: %v", err)
	}
}

func TestAttachToPod_WithStdinStillAttempts(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "podtrace"}}},
	}
	cs, cfg := newAttachClientset(t, pod)

	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	streams := genericiooptions.IOStreams{
		In:     bytes.NewBufferString("stdin data"),
		Out:    out,
		ErrOut: errOut,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := AttachToPod(ctx, cfg, cs, pod, streams); err == nil {
		t.Fatalf("expected a stream error with stdin enabled too")
	}
}

func TestRunOneNode_AttachFailureIsDiagnosed(t *testing.T) {
	useClassicListWatch(t)
	shortDiagnoseTiming(t, 50*time.Millisecond, 10*time.Millisecond)

	cs, cfg := newAttachClientset(t)
	runningOnCreate(cs.Clientset)

	spec := spawnPodSpec(t, "ns1")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	opts := RunOptions{
		Clientset:  cs,
		RestConfig: cfg,
		Streams:    genericiooptions.IOStreams{Out: out, ErrOut: errOut},
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "")
	if err == nil {
		t.Fatalf("expected an attach-failure error")
	}
	var afe *AttachFailedError
	if !errors.As(err, &afe) {
		t.Fatalf("expected *AttachFailedError from diagnose, got %T: %v", err, err)
	}

	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), spec.Name, metav1.GetOptions{}); gerr == nil {
		t.Errorf("spawn pod should have been cleaned up after attach failure")
	}
}
