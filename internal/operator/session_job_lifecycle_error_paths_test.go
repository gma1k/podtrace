package operator

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func failNthList[T client.ObjectList](n int) func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
	calls := 0
	return func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(T); ok {
			calls++
			if calls == n {
				return errInternal()
			}
		}
		return c.List(ctx, list, opts...)
	}
}

func TestSessionReconcile_JobNamespaceListErrorIsReturned(t *testing.T) {
	s := fannedOutSession()
	r := revocationReconciler(t, interceptor.Funcs{List: failNthList[*podtracev1alpha1.TracerConfigList](2)},
		append(sessMoreFanOutObjects()[1:], s)...)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed system-namespace list must surface as an error")
	}
}

func TestEnsureJobs_ExistingJobListErrorIsReturned(t *testing.T) {
	s := fannedOutSession()
	r := revocationReconciler(t, interceptor.Funcs{List: failNthList[*batchv1.JobList](2)},
		append(sessMoreFanOutObjects()[1:], s)...)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed Job list in ensureJobs must surface as an error")
	}
	if jobs := sessionJobsOnNode(t, r.Client, "n1"); len(jobs) != 0 {
		t.Fatalf("no Job may be created while the list fails: %+v", jobs)
	}
}

func TestTerminalSession_OwnedJobListErrorIsReturned(t *testing.T) {
	s := failedSessionWithRunningSibling()
	r := revocationReconciler(t, interceptor.Funcs{List: failNthList[*batchv1.JobList](1)}, s)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed Job list must surface as an error")
	}
}

func TestTerminalSession_GrantCheckErrorIsReturned(t *testing.T) {
	s := failedSessionWithRunningSibling()
	r := revocationReconciler(t, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Namespace); ok {
				return errInternal()
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}, s, tenantNamespace(""), jobTracing(s, "--namespaces", "tenant-b"))

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed grant lookup must surface as an error")
	}
	if !sessionJobExists(t, r.Client, s) {
		t.Fatal("a Job must not be stopped on an unreadable grant")
	}
}

func TestTerminalSession_PodReadCleanupErrorIsReturned(t *testing.T) {
	s := failedSessionWithRunningSibling()
	objects := append([]client.Object{s, tenantNamespace(""), jobTracing(s, "--namespaces", "tenant-b")}, podReadGrant(s, "tenant-b")...)
	r := revocationReconciler(t, interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*rbacv1.RoleBinding); ok {
				return errInternal()
			}
			return c.Delete(ctx, obj, opts...)
		},
	}, objects...)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed pod-read cleanup must surface as an error")
	}
	if sessionJobExists(t, r.Client, s) {
		t.Fatal("the Job must be stopped before the RBAC cleanup is attempted")
	}
}

func TestTerminalSession_StatusUpdateErrorIsReturned(t *testing.T) {
	s := failedSessionWithRunningSibling()
	r := revocationReconciler(t, interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			return errInternal()
		},
	}, s, tenantNamespace(""), jobTracing(s, "--namespaces", "tenant-b"))

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed status update must surface as an error")
	}
	if sessionJobExists(t, r.Client, s) {
		t.Fatal("the Job must be stopped even when the status write fails")
	}
}
