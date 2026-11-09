package nodespawn

import (
	"context"
	"io"
	"strings"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// EnvAttachHandshake tells the spawned podtrace to wait for the CLI before
// it writes anything.
const EnvAttachHandshake = "PODTRACE_ATTACH_HANDSHAKE"

// AttachHandshakeTimeout bounds how long the child waits for the handshake.
// An attach the CLI was allowed but never completed must not stall a trace.
var AttachHandshakeTimeout = 30 * time.Second

const attachHandshake = "\n"

// CanAttach reports whether the caller may attach to pods in namespace. A
// caller refused pods/attach streams pods/log instead, which replays the
// pod's output from its start and needs no handshake.
func CanAttach(ctx context.Context, clientset kubernetes.Interface, namespace string) bool {
	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace:   namespace,
				Verb:        "create",
				Resource:    "pods",
				Subresource: "attach",
			},
		},
	}
	got, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil || got == nil {
		return true
	}
	return got.Status.Allowed
}

// withHandshake prefixes the attach stdin with the handshake byte.
func withHandshake(in io.Reader) io.Reader {
	if in == nil {
		return strings.NewReader(attachHandshake)
	}
	return io.MultiReader(strings.NewReader(attachHandshake), in)
}

// AwaitAttachHandshake blocks until one byte arrives on in, in closes, or
// timeout passes, and reports whether the CLI was heard from.
func AwaitAttachHandshake(in io.Reader, timeout time.Duration) bool {
	heard := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1)
		_, _ = in.Read(buf)
		heard <- struct{}{}
	}()
	select {
	case <-heard:
		return true
	case <-time.After(timeout):
		return false
	}
}
