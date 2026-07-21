package operator

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
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

func TestTC_CountActiveSessions_CountsNonTerminal(t *testing.T) {
	scheme := newOperatorScheme(t)
	mk := func(name string, state podtracev1alpha1.SessionState) *podtracev1alpha1.PodTraceSession {
		return &podtracev1alpha1.PodTraceSession{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
			Status:     podtracev1alpha1.PodTraceSessionStatus{State: state},
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		mk("pending", podtracev1alpha1.SessionStatePending),
		mk("running", podtracev1alpha1.SessionStateRunning),
		mk("done", podtracev1alpha1.SessionStateCompleted),
		mk("failed", podtracev1alpha1.SessionStateFailed),
		mk("empty", ""),
	).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if got := r.countActiveSessions(context.Background()); got != 3 {
		t.Errorf("active = %d, want 3 (pending+running+empty)", got)
	}

	errC := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.PodTraceSessionList); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	rErr := &TracerConfigReconciler{Client: errC, Scheme: scheme}
	if got := rErr.countActiveSessions(context.Background()); got != 0 {
		t.Errorf("active on List error = %d, want 0", got)
	}
}

func TestTC_CleanupStaleAgentNamespaces_DeletesOtherNamespaces(t *testing.T) {
	scheme := newOperatorScheme(t)
	agentLabels := map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent}
	const current, stale = "podtrace-system", "old-ns"

	staleObjs := []client.Object{
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: AgentDaemonSetName(), Namespace: stale, Labels: agentLabels}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: AgentServiceAccountName(), Namespace: stale, Labels: agentLabels}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: AgentBundleRoleName(), Namespace: stale, Labels: agentLabels}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: AgentBundleRoleBindingName(), Namespace: stale, Labels: agentLabels}},
	}
	currentObjs := []client.Object{
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: AgentDaemonSetName(), Namespace: current, Labels: agentLabels}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: AgentServiceAccountName(), Namespace: current, Labels: agentLabels}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(append(staleObjs, currentObjs...)...).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: current}

	if err := r.cleanupStaleAgentNamespaces(context.Background(), current); err != nil {
		t.Fatalf("cleanupStaleAgentNamespaces: %v", err)
	}

	ctx := context.Background()
	for _, o := range staleObjs {
		if err := c.Get(ctx, client.ObjectKeyFromObject(o), o.DeepCopyObject().(client.Object)); !apierrors.IsNotFound(err) {
			t.Errorf("stale %T should be deleted, got err=%v", o, err)
		}
	}

	var ds appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{Name: AgentDaemonSetName(), Namespace: current}, &ds); err != nil {
		t.Errorf("current DaemonSet must survive: %v", err)
	}
}

func TestTC_CleanupStaleAgentNamespaces_ListErrors(t *testing.T) {
	scheme := newOperatorScheme(t)
	cases := []struct {
		name string
		fail func(client.ObjectList) bool
	}{
		{"daemonsets", func(l client.ObjectList) bool { _, ok := l.(*appsv1.DaemonSetList); return ok }},
		{"serviceaccounts", func(l client.ObjectList) bool { _, ok := l.(*corev1.ServiceAccountList); return ok }},
		{"roles", func(l client.ObjectList) bool { _, ok := l.(*rbacv1.RoleList); return ok }},
		{"rolebindings", func(l client.ObjectList) bool { _, ok := l.(*rbacv1.RoleBindingList); return ok }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(scheme).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
						if tc.fail(list) {
							return errInternal()
						}
						return nil
					},
				}).Build()
			r := &TracerConfigReconciler{Client: c, Scheme: scheme}
			if err := r.cleanupStaleAgentNamespaces(context.Background(), "podtrace-system"); err == nil {
				t.Fatalf("expected error when listing %s fails", tc.name)
			}
		})
	}
}

func TestTC_EnsureAgentRBAC_Errors(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName}}

	cases := []struct {
		name string
		fail func(client.Object) bool
	}{
		{"serviceaccount", func(o client.Object) bool { _, ok := o.(*corev1.ServiceAccount); return ok }},
		{"clusterrole", func(o client.Object) bool { _, ok := o.(*rbacv1.ClusterRole); return ok }},
		{"clusterrolebinding", func(o client.Object) bool { _, ok := o.(*rbacv1.ClusterRoleBinding); return ok }},
		{"role", func(o client.Object) bool { _, ok := o.(*rbacv1.Role); return ok }},
		{"rolebinding", func(o client.Object) bool { _, ok := o.(*rbacv1.RoleBinding); return ok }},
	}
	for _, cse := range cases {
		t.Run(cse.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(scheme).
				WithInterceptorFuncs(interceptor.Funcs{
					Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						if cse.fail(obj) {
							return errInternal()
						}
						return cl.Create(ctx, obj, opts...)
					},
				}).Build()
			r := &TracerConfigReconciler{Client: c, Scheme: scheme}
			if err := r.ensureAgentRBAC(context.Background(), tc, "podtrace-system"); err == nil {
				t.Fatalf("expected error when creating %s fails", cse.name)
			}
		})
	}
}

func TestTC_Reconcile_BTFModeEmbedded(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName, Generation: 3},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:   "ghcr.io/gma1k/podtrace:test",
			BTFMode: podtracev1alpha1.BTFModeEmbedded,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ObservedGeneration != 3 {
		t.Errorf("ObservedGeneration = %d, want 3", got.Status.ObservedGeneration)
	}
	var ds appsv1.DaemonSet
	if err := c.Get(context.Background(), types.NamespacedName{Name: AgentDaemonSetName(), Namespace: "podtrace-system"}, &ds); err != nil {
		t.Errorf("agent DaemonSet not created: %v", err)
	}
}

func TestTC_Reconcile_NonDefaultStatusUpdateError(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: "custom"}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "custom"},
	}); err == nil {
		t.Fatal("expected error from failed status update on inert TracerConfig")
	}
}

func TestTC_Reconcile_RBACError(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err == nil {
		t.Fatal("expected RBAC error to propagate from Reconcile")
	}
}

func TestTC_Reconcile_CleanupStaleErrorLoggedNotFatal(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "img"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {

				if _, ok := list.(*appsv1.DaemonSetList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err != nil {
		t.Fatalf("stale cleanup error must not abort reconcile: %v", err)
	}
	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) == 0 {
		t.Error("status should still be written after non-fatal stale cleanup error")
	}
}
