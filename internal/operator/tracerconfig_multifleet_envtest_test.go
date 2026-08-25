//go:build envtest
// +build envtest

package operator

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func createFleetConfig(t *testing.T, c client.Client, name string, spec podtracev1alpha1.TracerConfigSpec) *podtracev1alpha1.TracerConfig {
	t.Helper()
	if spec.Image == "" {
		spec.Image = "ghcr.io/gma1k/podtrace:test"
	}
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Create(ctx, tc); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create TracerConfig %s: %v", name, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.Delete(cleanupCtx, tc)
	})
	return tc
}

func createFleetNode(t *testing.T, c client.Client, name string, labels map[string]string) {
	t.Helper()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Create(ctx, node); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create Node %s: %v", name, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.Delete(cleanupCtx, node)
	})
}

func TestEnvtestTwoFleetsOnDisjointNodes(t *testing.T) {
	scheme, c, _ := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)

	createFleetNode(t, c, "disjoint-a1", map[string]string{"pool": "disjoint-a"})
	createFleetNode(t, c, "disjoint-b1", map[string]string{"pool": "disjoint-b"})
	createFleetConfig(t, c, "fleet-a", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "disjoint-a"},
	})
	createFleetConfig(t, c, "fleet-b", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "disjoint-b"},
	})

	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, name := range []string{"fleet-a", "fleet-b"} {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
	}

	for _, tt := range []struct{ config, object, pool string }{
		{"fleet-a", "podtrace-agent-fleet-a", "disjoint-a"},
		{"fleet-b", "podtrace-agent-fleet-b", "disjoint-b"},
	} {
		var ds appsv1.DaemonSet
		if err := c.Get(ctx, types.NamespacedName{Name: tt.object, Namespace: systemNS}, &ds); err != nil {
			t.Fatalf("apiserver rejected or never received DaemonSet %s: %v", tt.object, err)
		}
		if got := ds.Spec.Template.Spec.NodeSelector["pool"]; got != tt.pool {
			t.Errorf("%s nodeSelector pool = %q, want %q", tt.object, got, tt.pool)
		}
		if got := ds.Spec.Template.Spec.ServiceAccountName; got != tt.object {
			t.Errorf("%s serviceAccountName = %q, want %q", tt.object, got, tt.object)
		}

		var sa corev1.ServiceAccount
		if err := c.Get(ctx, types.NamespacedName{Name: tt.object, Namespace: systemNS}, &sa); err != nil {
			t.Errorf("ServiceAccount %s: %v", tt.object, err)
		}
		var cr rbacv1.ClusterRole
		if err := c.Get(ctx, types.NamespacedName{Name: tt.object}, &cr); err != nil {
			t.Errorf("ClusterRole %s: %v", tt.object, err)
		}

		var got podtracev1alpha1.TracerConfig
		if err := c.Get(ctx, types.NamespacedName{Name: tt.config}, &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.MatchedNodes != 1 {
			t.Errorf("%s matchedNodes = %d, want 1", tt.config, got.Status.MatchedNodes)
		}
		if got.Status.ContestedNodes != 0 {
			t.Errorf("%s contestedNodes = %d, want 0 for disjoint pools", tt.config, got.Status.ContestedNodes)
		}
		cond := findCondition(got.Status.Conditions, ConditionConflict)
		if cond == nil || cond.Status != metav1.ConditionFalse {
			t.Errorf("%s must report Conflict=False, got %+v", tt.config, got.Status.Conditions)
		}
	}
}

func TestEnvtestUpgradeKeepsLegacyDaemonSetIdentity(t *testing.T) {
	scheme, c, _ := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)
	ensureDefaultTracerConfig(t, c)

	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	legacyKey := types.NamespacedName{Name: "podtrace-agent", Namespace: systemNS}
	var before appsv1.DaemonSet
	if err := c.Get(ctx, legacyKey, &before); err != nil {
		t.Fatalf("the default fleet must own the unsuffixed DaemonSet: %v", err)
	}

	createFleetConfig(t, c, "added-later", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "added-later"},
	})
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "added-later"},
	}); err != nil {
		t.Fatalf("reconcile added-later: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err != nil {
		t.Fatalf("second reconcile of default: %v", err)
	}

	var after appsv1.DaemonSet
	if err := c.Get(ctx, legacyKey, &after); err != nil {
		t.Fatalf("legacy DaemonSet disappeared after a second fleet was added: %v", err)
	}
	if after.UID != before.UID {
		t.Errorf("DaemonSet UID changed %q -> %q: adding a fleet must not recreate the existing one, which would drop the agent on every node at once",
			before.UID, after.UID)
	}

	var added appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{
		Name: "podtrace-agent-added-later", Namespace: systemNS,
	}, &added); err != nil {
		t.Errorf("the new fleet must get its own suffixed DaemonSet: %v", err)
	}
}

func TestEnvtestOverlappingFleetsReportConflict(t *testing.T) {
	scheme, c, _ := setupSharedEnvtest(t)
	systemNS := ensureSystemNamespace(t, c)

	createFleetNode(t, c, "contested-1", map[string]string{"pool": "shared", "zone": "shared-eu"})
	createFleetConfig(t, c, "wins", podtracev1alpha1.TracerConfigSpec{
		NodeSelector:  map[string]string{"pool": "shared"},
		FleetPriority: 10,
	})
	createFleetConfig(t, c, "loses", podtracev1alpha1.TracerConfigSpec{
		NodeSelector:  map[string]string{"zone": "shared-eu"},
		FleetPriority: 1,
	})

	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, name := range []string{"wins", "loses"} {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
	}

	for _, name := range []string{"wins", "loses"} {
		var got podtracev1alpha1.TracerConfig
		if err := c.Get(ctx, types.NamespacedName{Name: name}, &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.ContestedNodes != 1 {
			t.Errorf("%s contestedNodes = %d, want 1", name, got.Status.ContestedNodes)
		}
		cond := findCondition(got.Status.Conditions, ConditionConflict)
		if cond == nil || cond.Status != metav1.ConditionTrue {
			t.Errorf("%s must report Conflict=True, got %+v", name, got.Status.Conditions)
		}
	}

	var winner appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{Name: "podtrace-agent-wins", Namespace: systemNS}, &winner); err != nil {
		t.Errorf("overlap is reported, not enforced: the winner keeps its DaemonSet: %v", err)
	}
	var loser appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{Name: "podtrace-agent-loses", Namespace: systemNS}, &loser); err != nil {
		t.Errorf("overlap is reported, not enforced: the loser keeps its DaemonSet too: %v", err)
	}
}

func TestEnvtestFleetsWithDifferentSystemNamespacesCoexist(t *testing.T) {
	scheme, c, _ := setupSharedEnvtest(t)
	nsA := ensureDedicatedSystemNamespace(t, c, "coexist-a")
	nsB := ensureDedicatedSystemNamespace(t, c, "coexist-b")

	createFleetConfig(t, c, "coexist-a", podtracev1alpha1.TracerConfigSpec{
		SystemNamespace: nsA,
		NodeSelector:    map[string]string{"pool": "coexist-a"},
	})
	createFleetConfig(t, c, "coexist-b", podtracev1alpha1.TracerConfigSpec{
		SystemNamespace: nsB,
		NodeSelector:    map[string]string{"pool": "coexist-b"},
	})

	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: nsA}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Three rounds: the flapping regression only shows once each config has
	// reconciled at least twice, because each pass is what would delete the
	// other's DaemonSet.
	for round := 0; round < 3; round++ {
		for _, name := range []string{"coexist-a", "coexist-b"} {
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
				t.Fatalf("round %d reconcile %s: %v", round, name, err)
			}
		}

		for _, tt := range []struct{ name, namespace string }{
			{"podtrace-agent-coexist-a", nsA},
			{"podtrace-agent-coexist-b", nsB},
		} {
			var ds appsv1.DaemonSet
			if err := c.Get(ctx, types.NamespacedName{Name: tt.name, Namespace: tt.namespace}, &ds); err != nil {
				t.Fatalf("round %d: %s/%s missing — a fleet deleted a sibling's DaemonSet, which flaps forever and leaves the cluster with no agents: %v",
					round, tt.namespace, tt.name, err)
			}
		}
	}

	var strays appsv1.DaemonSetList
	if err := c.List(ctx, &strays, client.InNamespace(nsA), client.MatchingLabels{
		LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent,
	}); err != nil {
		t.Fatal(err)
	}
	for i := range strays.Items {
		if strays.Items[i].Labels[LabelTracerConfig] != "coexist-a" {
			t.Errorf("namespace %s holds DaemonSet %s belonging to fleet %q",
				nsA, strays.Items[i].Name, strays.Items[i].Labels[LabelTracerConfig])
		}
	}
}
