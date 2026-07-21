package operator

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestReaper_NeedLeaderElection(t *testing.T) {
	r := &SessionChildReaper{}
	if !r.NeedLeaderElection() {
		t.Error("SessionChildReaper must require leader election")
	}
}

func TestReaper_Start_RunsOnceThenStopsOnCancel(t *testing.T) {
	scheme := newOperatorScheme(t)
	orphan := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:      "podtrace-gone-n1",
		Namespace: "podtrace-system",
		Labels:    reaperSessionLabels("gone", "team-a"),
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphan).Build()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &SessionChildReaper{Client: c}
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
}

func TestReaper_Start_ReapErrorLogged(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errInternal()
			},
		}).Build()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &SessionChildReaper{Client: c, Interval: time.Hour, Grace: time.Minute}
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start must swallow sweep errors, got %v", err)
	}
}

func TestReapOrphan_ListErrors(t *testing.T) {
	scheme := newOperatorScheme(t)
	cases := []struct {
		name string
		fail func(client.ObjectList) bool
	}{
		{"jobs", func(l client.ObjectList) bool { _, ok := l.(*batchv1.JobList); return ok }},
		{"configmaps", func(l client.ObjectList) bool { _, ok := l.(*corev1.ConfigMapList); return ok }},
		{"secrets", func(l client.ObjectList) bool { _, ok := l.(*corev1.SecretList); return ok }},
		{"serviceaccounts", func(l client.ObjectList) bool { _, ok := l.(*corev1.ServiceAccountList); return ok }},
		{"roles", func(l client.ObjectList) bool { _, ok := l.(*rbacv1.RoleList); return ok }},
		{"rolebindings", func(l client.ObjectList) bool { _, ok := l.(*rbacv1.RoleBindingList); return ok }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(scheme).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if tc.fail(list) {
							return errInternal()
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()
			if _, err := reapOrphanSessionChildren(context.Background(), c, time.Now(), time.Minute); err == nil {
				t.Fatalf("expected error when listing %s fails", tc.name)
			}
		})
	}
}

func TestReapOrphan_GetSessionError(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := time.Now()
	orphan := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:              "podtrace-gone-n1",
		Namespace:         "podtrace-system",
		Labels:            reaperSessionLabels("gone", "team-a"),
		CreationTimestamp: metav1.NewTime(now.Add(-time.Hour)),
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphan).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()

	n, err := reapOrphanSessionChildren(context.Background(), c, now, time.Minute)
	if err != nil {
		t.Fatalf("reap error = %v", err)
	}
	if n != 0 {
		t.Errorf("reaped %d, want 0 when session lookup errors (fail-safe skip)", n)
	}
}

func TestReapOrphan_DeleteError(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := time.Now()
	orphan := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:              "podtrace-gone-n1",
		Namespace:         "podtrace-system",
		Labels:            reaperSessionLabels("gone", "team-a"),
		CreationTimestamp: metav1.NewTime(now.Add(-time.Hour)),
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphan).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
				return errInternal()
			},
		}).Build()

	if _, err := reapOrphanSessionChildren(context.Background(), c, now, time.Minute); err == nil {
		t.Fatal("expected delete error to propagate")
	}
}
