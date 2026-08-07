package operator

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func fleetConfig(name string, spec podtracev1alpha1.TracerConfigSpec) *podtracev1alpha1.TracerConfig {
	if spec.Image == "" {
		spec.Image = "ghcr.io/gma1k/podtrace:test"
	}
	return &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name)},
		Spec:       spec,
	}
}

func fleetNode(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func reconcileFleets(t *testing.T, objs []client.Object, names ...string) (client.Client, *TracerConfigReconciler) {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(objs...).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	for _, name := range names {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: name},
		}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
	}
	return c, r
}

func TestTwoFleetsGetSeparateDaemonSetsAndRBAC(t *testing.T) {
	c, _ := reconcileFleets(t,
		[]client.Object{
			fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{
				NodeSelector: map[string]string{"pool": "a"},
			}),
			fleetConfig("secondary", podtracev1alpha1.TracerConfigSpec{
				NodeSelector: map[string]string{"pool": "b"},
			}),
		},
		DefaultTracerConfigName, "secondary")

	ctx := context.Background()
	for _, tt := range []struct{ config, daemonSet string }{
		{DefaultTracerConfigName, "podtrace-agent"},
		{"secondary", "podtrace-agent-secondary"},
	} {
		var ds appsv1.DaemonSet
		key := types.NamespacedName{Name: tt.daemonSet, Namespace: "podtrace-system"}
		if err := c.Get(ctx, key, &ds); err != nil {
			t.Fatalf("DaemonSet %s: %v", tt.daemonSet, err)
		}
		if got := ds.Spec.Selector.MatchLabels[LabelTracerConfig]; got != tt.config {
			t.Errorf("%s pod selector %s = %q, want %q", tt.daemonSet, LabelTracerConfig, got, tt.config)
		}

		var sa corev1.ServiceAccount
		if err := c.Get(ctx, types.NamespacedName{Name: tt.daemonSet, Namespace: "podtrace-system"}, &sa); err != nil {
			t.Errorf("ServiceAccount %s: %v", tt.daemonSet, err)
		}
		var cr rbacv1.ClusterRole
		if err := c.Get(ctx, types.NamespacedName{Name: tt.daemonSet}, &cr); err != nil {
			t.Errorf("ClusterRole %s: %v", tt.daemonSet, err)
		}
		var crb rbacv1.ClusterRoleBinding
		if err := c.Get(ctx, types.NamespacedName{Name: tt.daemonSet}, &crb); err != nil {
			t.Errorf("ClusterRoleBinding %s: %v", tt.daemonSet, err)
		}
		if len(crb.Subjects) != 1 || crb.Subjects[0].Name != tt.daemonSet {
			t.Errorf("ClusterRoleBinding %s subjects = %+v, want the fleet's own SA", tt.daemonSet, crb.Subjects)
		}
	}
}

func TestDeletingOneFleetLeavesTheOthersRBACIntact(t *testing.T) {
	c, r := reconcileFleets(t,
		[]client.Object{
			fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{}),
			fleetConfig("secondary", podtracev1alpha1.TracerConfigSpec{}),
		},
		DefaultTracerConfigName, "secondary")

	ctx := context.Background()
	var doomed podtracev1alpha1.TracerConfig
	if err := c.Get(ctx, types.NamespacedName{Name: "secondary"}, &doomed); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, &doomed); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "secondary"},
	}); err != nil {
		t.Fatalf("reconcile after delete: %v", err)
	}

	var cr rbacv1.ClusterRole
	if err := c.Get(ctx, types.NamespacedName{Name: "podtrace-agent"}, &cr); err != nil {
		t.Errorf("the surviving fleet's ClusterRole must not be collected with its sibling: %v", err)
	}
	var ds appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{Name: "podtrace-agent", Namespace: "podtrace-system"}, &ds); err != nil {
		t.Errorf("the surviving fleet's DaemonSet must not be collected with its sibling: %v", err)
	}
}

func TestFleetCleanupDoesNotCrossFleets(t *testing.T) {
	scheme := newOperatorScheme(t)
	otherFleetDS := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Name:      "podtrace-agent-secondary",
		Namespace: "other-ns",
		Labels: map[string]string{
			LabelManagedBy:    ManagedByValue,
			LabelComponent:    ComponentAgent,
			LabelTracerConfig: "secondary",
		},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(otherFleetDS).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if err := r.cleanupStaleAgentObjects(context.Background(), DefaultTracerConfigName, "podtrace-system"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var survivor appsv1.DaemonSet
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(otherFleetDS), &survivor); err != nil {
		t.Fatalf("a fleet must never delete another fleet's DaemonSet, even in a foreign namespace: %v", err)
	}
}

func TestDefaultFleetAdoptsUnlabelledLegacyObjects(t *testing.T) {
	scheme := newOperatorScheme(t)
	legacy := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Name:      "podtrace-agent",
		Namespace: "old-ns",
		Labels: map[string]string{
			LabelManagedBy: ManagedByValue,
			LabelComponent: ComponentAgent,
		},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(legacy).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if err := r.cleanupStaleAgentObjects(context.Background(), DefaultTracerConfigName, "podtrace-system"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var got appsv1.DaemonSet
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(legacy), &got); !apierrors.IsNotFound(err) {
		t.Errorf("a pre-multi-config agent object with no tracer-config label belongs to the default fleet and must be collected, got err=%v", err)
	}
}

func TestDefaultFleetKeepsLegacyDaemonSetName(t *testing.T) {
	c, _ := reconcileFleets(t,
		[]client.Object{fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{})},
		DefaultTracerConfigName)

	ctx := context.Background()
	var ds appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{Name: "podtrace-agent", Namespace: "podtrace-system"}, &ds); err != nil {
		t.Fatalf("the default fleet must keep the unsuffixed name so single-config clusters upgrade in place: %v", err)
	}
	var suffixed appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{
		Name: "podtrace-agent-default", Namespace: "podtrace-system",
	}, &suffixed); !apierrors.IsNotFound(err) {
		t.Errorf("the default fleet must not also create a suffixed DaemonSet, got err=%v", err)
	}
}

func TestExistingDaemonSetIsUpdatedNotRecreated(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{})
	existing := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Name:      "podtrace-agent",
		Namespace: "podtrace-system",
		UID:       "pre-upgrade-uid",
		Labels: map[string]string{
			LabelManagedBy:    ManagedByValue,
			LabelComponent:    ComponentAgent,
			LabelTracerConfig: DefaultTracerConfigName,
		},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc, existing).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got appsv1.DaemonSet
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(existing), &got); err != nil {
		t.Fatal(err)
	}
	if got.UID != "pre-upgrade-uid" {
		t.Errorf("DaemonSet UID = %q, want it unchanged: recreating it drops the agent on every node at once", got.UID)
	}
}

func TestOverlappingFleetsReportConflict(t *testing.T) {
	c, _ := reconcileFleets(t,
		[]client.Object{
			fleetConfig("by-pool", podtracev1alpha1.TracerConfigSpec{
				NodeSelector: map[string]string{"pool": "a"},
				Priority:     5,
			}),
			fleetConfig("by-zone", podtracev1alpha1.TracerConfigSpec{
				NodeSelector: map[string]string{"zone": "eu-1"},
			}),
			fleetNode("shared", map[string]string{"pool": "a", "zone": "eu-1"}),
			fleetNode("pool-only", map[string]string{"pool": "a"}),
		},
		"by-pool", "by-zone")

	ctx := context.Background()
	var loser podtracev1alpha1.TracerConfig
	if err := c.Get(ctx, types.NamespacedName{Name: "by-zone"}, &loser); err != nil {
		t.Fatal(err)
	}
	if loser.Status.ContestedNodes != 1 {
		t.Errorf("by-zone contestedNodes = %d, want 1", loser.Status.ContestedNodes)
	}
	if loser.Status.MatchedNodes != 1 {
		t.Errorf("by-zone matchedNodes = %d, want 1", loser.Status.MatchedNodes)
	}
	cond := findCondition(loser.Status.Conditions, ConditionConflict)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("by-zone must report Conflict=True, got %+v", loser.Status.Conditions)
	}
	if !strings.Contains(cond.Message, "shared") {
		t.Errorf("conflict message must name the contested node, got %q", cond.Message)
	}
	if !strings.Contains(cond.Message, "outranked") {
		t.Errorf("the lower-priority config must be told it is outranked, got %q", cond.Message)
	}

	var winner podtracev1alpha1.TracerConfig
	if err := c.Get(ctx, types.NamespacedName{Name: "by-pool"}, &winner); err != nil {
		t.Fatal(err)
	}
	if winner.Status.MatchedNodes != 2 {
		t.Errorf("by-pool matchedNodes = %d, want 2", winner.Status.MatchedNodes)
	}
	if cond := findCondition(winner.Status.Conditions, ConditionConflict); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("both sides of an overlap are affected, so the winner reports Conflict too, got %+v", winner.Status.Conditions)
	}
}

func TestDisjointFleetsReportNoConflict(t *testing.T) {
	c, _ := reconcileFleets(t,
		[]client.Object{
			fleetConfig("pool-a", podtracev1alpha1.TracerConfigSpec{
				NodeSelector: map[string]string{"pool": "a"},
			}),
			fleetConfig("pool-b", podtracev1alpha1.TracerConfigSpec{
				NodeSelector: map[string]string{"pool": "b"},
			}),
			fleetNode("a1", map[string]string{"pool": "a"}),
			fleetNode("b1", map[string]string{"pool": "b"}),
		},
		"pool-a", "pool-b")

	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pool-a"}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionConflict)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Errorf("disjoint fleets must report Conflict=False, got %+v", got.Status.Conditions)
	}
	if got.Status.ContestedNodes != 0 {
		t.Errorf("contestedNodes = %d, want 0", got.Status.ContestedNodes)
	}
}

func TestOverlongNameIsRejectedBeforeBuildingAnything(t *testing.T) {
	long := strings.Repeat("x", podtracev1alpha1.MaxTracerConfigNameLength+1)
	c, _ := reconcileFleets(t,
		[]client.Object{fleetConfig(long, podtracev1alpha1.TracerConfigSpec{})},
		long)

	ctx := context.Background()
	var got podtracev1alpha1.TracerConfig
	if err := c.Get(ctx, types.NamespacedName{Name: long}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "InvalidName" {
		t.Fatalf("an over-long name must degrade the config, got %+v", got.Status.Conditions)
	}

	var ds appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{
		Name: "podtrace-agent-" + long, Namespace: "podtrace-system",
	}, &ds); !apierrors.IsNotFound(err) {
		t.Errorf("no DaemonSet may be built for an unusable name, got err=%v", err)
	}
}

func TestPartitionSurvivesMissingNodesPermission(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(nodeListForbidden()).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err != nil {
		t.Fatalf("losing overlap detection must not fail the reconcile: %v", err)
	}

	ctx := context.Background()
	var ds appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{Name: "podtrace-agent", Namespace: "podtrace-system"}, &ds); err != nil {
		t.Errorf("the agent fleet must still be reconciled without nodes RBAC: %v", err)
	}

	var got podtracev1alpha1.TracerConfig
	if err := c.Get(ctx, types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionConflict)
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "NodesUnreadable" {
		t.Errorf("unreadable nodes must surface as Conflict=Unknown, got %+v", got.Status.Conditions)
	}
}

func nodeListForbidden() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.NodeList); ok {
				return apierrors.NewForbidden(
					schema.GroupResource{Resource: "nodes"}, "", errors.New("no nodes RBAC"))
			}
			return c.List(ctx, list, opts...)
		},
	}
}
