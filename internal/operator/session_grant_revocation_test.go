package operator

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func crossNamespaceSession() *podtracev1alpha1.PodTraceSession {
	s := fannedOutSession()
	s.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "b"}}
	return s
}

func jobTracing(s *podtracev1alpha1.PodTraceSession, args ...string) *batchv1.Job {
	job := runningSessionJob(s, "n1")
	job.Spec.Template.Spec.Containers[0].Args = args
	return job
}

func revocationReconciler(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) *PodTraceSessionReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objects...).
		WithInterceptorFuncs(funcs).Build()
	return &PodTraceSessionReconciler{
		Client:          c,
		Scheme:          scheme,
		SystemNamespace: sessMoreSysNS,
		nowFn:           func() time.Time { return pendingDeadlineCreated.Add(time.Minute) },
	}
}

func sessionJobExists(t *testing.T, c client.Client, s *podtracev1alpha1.PodTraceSession) bool {
	t.Helper()
	var job batchv1.Job
	err := c.Get(context.Background(), types.NamespacedName{Namespace: sessMoreSysNS, Name: SessionJobName(s.UID, "n1")}, &job)
	return err == nil
}

func podReadGrant(s *podtracev1alpha1.PodTraceSession, namespace string) []client.Object {
	labels := sessionChildLabels(s)
	return []client.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleName(s.UID), Namespace: namespace, Labels: labels}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleBindingName(s.UID), Namespace: namespace, Labels: labels}},
	}
}

func podReadGrantLeft(t *testing.T, c client.Client, namespace string) int {
	t.Helper()
	var roles rbacv1.RoleList
	var bindings rbacv1.RoleBindingList
	if err := c.List(context.Background(), &roles, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	if err := c.List(context.Background(), &bindings, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	return len(roles.Items) + len(bindings.Items)
}

func degradedReason(s podtracev1alpha1.PodTraceSession) (string, string) {
	for _, cond := range s.Status.Conditions {
		if cond.Type == ConditionDegraded {
			return cond.Reason, cond.Message
		}
	}
	return "", ""
}

func TestSessionReconcile_WithdrawnGrantStopsRunningJob(t *testing.T) {
	cases := map[string][]string{
		"namespace selector": {"--pod-selector", "a=b", "--all-in-namespace", "--namespaces", "tenant-b"},
		"pod reference":      {"--pods", "tenant-b/p2"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			s := crossNamespaceSession()
			objects := append(sessMoreFanOutObjects()[1:], s, tenantNamespace(""), jobTracing(s, args...))
			objects = append(objects, podReadGrant(s, "tenant-b")...)
			r := revocationReconciler(t, interceptor.Funcs{}, objects...)

			if _, err := sessMoreReconcile(t, r); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if sessionJobExists(t, r.Client, s) {
				t.Fatal("a Job tracing a namespace that withdrew its grant must be stopped")
			}
			if left := podReadGrantLeft(t, r.Client, "tenant-b"); left != 0 {
				t.Errorf("%d pod-read RBAC object(s) left in the namespace that withdrew its grant", left)
			}
			got := (&fakeGetter{r: r}).session(t)
			if got.Status.State != podtracev1alpha1.SessionStateFailed {
				t.Fatalf("state = %q, want Failed", got.Status.State)
			}
			if reason, message := degradedReason(got); reason != "CrossNamespaceGrantRevoked" || !strings.Contains(message, "[tenant-b]") {
				t.Errorf("Degraded = %s: %q, want CrossNamespaceGrantRevoked naming tenant-b", reason, message)
			}
		})
	}
}

func TestSessionReconcile_JobKeepsRunningWithoutWithdrawal(t *testing.T) {
	terminating := tenantNamespace("")
	now := metav1.Now()
	terminating.DeletionTimestamp = &now
	terminating.Finalizers = []string{"kubernetes"}

	cases := map[string]struct {
		namespace *corev1.Namespace
		args      []string
		complete  bool
	}{
		"grant still present":       {namespace: tenantNamespace("default"), args: []string{"--namespaces", "tenant-b"}},
		"wildcard grant":            {namespace: tenantNamespace(podtracev1alpha1.AllowTracingFromWildcard), args: []string{"--pods", "tenant-b/p2"}},
		"namespace deleted":         {args: []string{"--namespaces", "tenant-b"}},
		"namespace terminating":     {namespace: terminating, args: []string{"--namespaces", "tenant-b"}},
		"own namespace only":        {namespace: tenantNamespace(""), args: []string{"--namespace", "default"}},
		"job already finished":      {namespace: tenantNamespace(""), args: []string{"--namespaces", "tenant-b"}, complete: true},
		"job built before any args": {namespace: tenantNamespace("")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := crossNamespaceSession()
			job := jobTracing(s, tc.args...)
			if tc.complete {
				job.Status = batchv1.JobStatus{Succeeded: 1}
			}
			objects := append(sessMoreFanOutObjects()[1:], s, job)
			if tc.namespace != nil {
				objects = append(objects, tc.namespace)
			}
			r := revocationReconciler(t, interceptor.Funcs{}, objects...)

			if _, err := sessMoreReconcile(t, r); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if !sessionJobExists(t, r.Client, s) {
				t.Fatal("the Job must keep running when no grant was withdrawn")
			}
			if reason, _ := degradedReason((&fakeGetter{r: r}).session(t)); reason == "CrossNamespaceGrantRevoked" {
				t.Error("the session must not fail for a grant that was not withdrawn")
			}
		})
	}
}

func TestSessionReconcile_GrantCheckErrorsAreSurfaced(t *testing.T) {
	cases := map[string]interceptor.Funcs{
		"namespace read": {
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		},
		"job delete": {
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*batchv1.Job); ok {
					return errInternal()
				}
				return cl.Delete(ctx, obj, opts...)
			},
		},
		"pod-read prune": {
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*rbacv1.RoleBindingList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		},
		"job list": {
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*batchv1.JobList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		},
	}
	for name, funcs := range cases {
		t.Run(name, func(t *testing.T) {
			s := crossNamespaceSession()
			objects := append(sessMoreFanOutObjects()[1:], s, tenantNamespace(""), jobTracing(s, "--namespaces", "tenant-b"))
			r := revocationReconciler(t, funcs, objects...)

			if _, err := sessMoreReconcile(t, r); err == nil {
				t.Fatalf("a failed %s during the grant check must be returned for a retry", name)
			}
		})
	}
}

func TestSessionJobTracedNamespaces(t *testing.T) {
	job := &batchv1.Job{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "other", Args: []string{"--namespaces", "ignored"}},
			{Name: sessionContainerName, Args: []string{
				"--diagnose", "1m",
				"--namespace", "own",
				"--namespaces", "b,,c",
				"--pods", "d/p1,own/p2,malformed",
				"--namespaces",
			}},
		},
	}}}}
	got := sessionJobTracedNamespaces(job)
	if want := []string{"b", "c", "d", "own"}; !reflect.DeepEqual(got, want) {
		t.Errorf("traced namespaces = %v, want %v", got, want)
	}
}
