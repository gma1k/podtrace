package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

const finTestSysNS = "podtrace-system"

// finTestSession returns a PodTraceSession with a stable UID/namespace used
// across the cleanup tests.
func finTestSession() *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sess",
			Namespace: "team-a",
			UID:       types.UID("sess-uid"),
		},
	}
}

// finSessionJob builds a per-node session Job in the system namespace with the
// label set cleanupPodTraceSessionChildren lists by.
func finSessionJob(name, node string, withUID bool) *batchv1.Job {
	j := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: finTestSysNS,
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: "sess",
				LabelSessionNS:   "team-a",
				LabelNodeName:    node,
			},
		},
	}
	if withUID {
		j.UID = types.UID("job-" + name)
	}
	return j
}

// TestFin_CleanupSessionChildren_DeletesAll seeds the full child set (a Job,
// the bundle ConfigMap + Secret, the object-store creds Secret, and the
// per-session Role + RoleBinding) and asserts cleanupPodTraceSessionChildren
// removes every one of them.
func TestFin_CleanupSessionChildren_DeletesAll(t *testing.T) {
	s := finTestSession()
	scheme := newOperatorScheme(t)

	job := finSessionJob("job-n1", "n1", true)
	bundleCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: SessionBundleName(s.UID), Namespace: finTestSysNS}}
	bundleSec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: SessionBundleName(s.UID), Namespace: finTestSysNS}}
	credsSec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: SessionObjectStoreCredsName(s.UID), Namespace: finTestSysNS}}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: SessionReportRoleName(s.UID), Namespace: s.Namespace}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: SessionReportRoleBindingName(s.UID), Namespace: s.Namespace}}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(job, bundleCM, bundleSec, credsSec, role, rb).Build()

	ctx := context.Background()
	if err := cleanupPodTraceSessionChildren(ctx, c, s, finTestSysNS); err != nil {
		t.Fatalf("cleanup error = %v, want nil", err)
	}

	mustBeGone := func(name, ns string, obj client.Object) {
		err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, obj)
		if !apierrors.IsNotFound(err) {
			t.Errorf("%T %s/%s still present (err=%v), want NotFound", obj, ns, name, err)
		}
	}
	mustBeGone(job.Name, finTestSysNS, &batchv1.Job{})
	mustBeGone(bundleCM.Name, finTestSysNS, &corev1.ConfigMap{})
	mustBeGone(credsSec.Name, finTestSysNS, &corev1.Secret{})
	mustBeGone(role.Name, s.Namespace, &rbacv1.Role{})
	mustBeGone(rb.Name, s.Namespace, &rbacv1.RoleBinding{})
}

// TestFin_CleanupSessionChildren_NothingToDelete covers the idempotent path:
// with no children present every Delete returns NotFound (ignored) and the
// Job list is empty, so cleanup succeeds without error.
func TestFin_CleanupSessionChildren_NothingToDelete(t *testing.T) {
	s := finTestSession()
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()

	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, finTestSysNS); err != nil {
		t.Fatalf("cleanup with no children error = %v, want nil", err)
	}
}

// TestFin_CleanupSessionChildren_SkipsZeroUIDJob covers the j.UID == "" guard:
// a listed Job without a UID is skipped (never Deleted). We assert the Job is
// still present after cleanup and that a real Delete would have been a no-op by
// failing the test if the interceptor's Delete is ever invoked for that Job.
func TestFin_CleanupSessionChildren_SkipsZeroUIDJob(t *testing.T) {
	s := finTestSession()
	noUIDJob := finSessionJob("job-noid", "n1", false)

	deleteCalledForJob := false
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithObjects(noUIDJob).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if j, ok := obj.(*batchv1.Job); ok && j.Name == "job-noid" {
					deleteCalledForJob = true
				}
				return cl.Delete(ctx, obj, opts...)
			},
		}).Build()

	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, finTestSysNS); err != nil {
		t.Fatalf("cleanup error = %v, want nil", err)
	}
	if deleteCalledForJob {
		t.Errorf("Delete was called for the zero-UID Job; it should be skipped")
	}
}

// TestFin_CleanupSessionChildren_ListError covers the list-Jobs failure branch.
func TestFin_CleanupSessionChildren_ListError(t *testing.T) {
	s := finTestSession()
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errors.New("list boom")
			},
		}).Build()

	err := cleanupPodTraceSessionChildren(context.Background(), c, s, finTestSysNS)
	if err == nil {
		t.Fatal("expected error from list failure, got nil")
	}
	if got := err.Error(); !contains(got, "list session Jobs") {
		t.Errorf("error = %q, want it to mention list session Jobs", got)
	}
}

// TestFin_CleanupSessionChildren_JobDeleteError covers the non-NotFound error
// branch of the per-Job Delete loop.
func TestFin_CleanupSessionChildren_JobDeleteError(t *testing.T) {
	s := finTestSession()
	job := finSessionJob("job-n1", "n1", true)
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithObjects(job).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*batchv1.Job); ok {
					return errors.New("delete job boom")
				}
				return nil
			},
		}).Build()

	err := cleanupPodTraceSessionChildren(context.Background(), c, s, finTestSysNS)
	if err == nil {
		t.Fatal("expected error from Job delete failure, got nil")
	}
	if got := err.Error(); !contains(got, "delete Job") {
		t.Errorf("error = %q, want it to mention delete Job", got)
	}
}

// TestFin_CleanupSessionChildren_RBACError covers the cleanupSessionReportRBAC
// failure branch: the bundle deletes succeed but the RBAC Role/RoleBinding
// delete returns a non-NotFound error.
func TestFin_CleanupSessionChildren_RBACError(t *testing.T) {
	s := finTestSession()
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				switch obj.(type) {
				case *rbacv1.Role, *rbacv1.RoleBinding:
					return errors.New("rbac delete boom")
				default:
					return nil
				}
			},
		}).Build()

	err := cleanupPodTraceSessionChildren(context.Background(), c, s, finTestSysNS)
	if err == nil {
		t.Fatal("expected error from RBAC delete failure, got nil")
	}
	if got := err.Error(); !contains(got, "session RBAC") {
		t.Errorf("error = %q, want it to mention session RBAC", got)
	}
}

// TestFin_ScheduleReconcile_GetError covers the non-NotFound Get error path at
// the top of Reconcile.
func TestFin_ScheduleReconcile_GetError(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(newOperatorScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errors.New("get boom")
			},
		}).Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: c.Scheme(), nowFn: func() time.Time { return fixedScheduleNow }}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "x", Namespace: "default"},
	})
	if err == nil {
		t.Fatal("expected error from Get failure, got nil")
	}
	if got := err.Error(); !contains(got, "get PodTraceSchedule") {
		t.Errorf("error = %q, want it to mention get PodTraceSchedule", got)
	}
}

// TestFin_ScheduleReconcile_NamespaceTerminating covers the
// ensureSessionForRun Forbidden+"being terminated" branch: a due schedule
// whose session creation is rejected because the namespace is terminating
// must exit cleanly (no error, empty result) rather than stack-trace.
func TestFin_ScheduleReconcile_NamespaceTerminating(t *testing.T) {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "due",
			Namespace:         "default",
			UID:               "due-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-6 * time.Minute)),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(newOperatorScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(sch).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return apierrors.NewForbidden(
						podtracev1alpha1.GroupVersion.WithResource("podtracesessions").GroupResource(),
						"due-session",
						errors.New("unable to create new content in namespace default because it is being terminated"),
					)
				}
				return nil
			},
		}).Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: c.Scheme(), nowFn: func() time.Time { return fixedScheduleNow }}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile(namespace terminating) error = %v, want nil", err)
	}
	if res != (ctrl.Result{}) {
		t.Fatalf("Reconcile(namespace terminating) result = %+v, want empty", res)
	}
}
