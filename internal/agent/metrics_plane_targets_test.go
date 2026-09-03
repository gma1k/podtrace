package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gma1k/podtrace/pkg/tracer"
)

func podEntry(namespace, name, container string, cgroupID uint64) PodCgroupEntry {
	return podEntryOwnedBy(namespace, name, name+"-7d9f8b6c5d", container, cgroupID)
}

func podEntryOwnedBy(namespace, pod, replicaSet, container string, cgroupID uint64) PodCgroupEntry {
	return PodCgroupEntry{
		Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      pod,
				OwnerReferences: []metav1.OwnerReference{{
					Kind:       "ReplicaSet",
					Name:       replicaSet,
					Controller: ptr(true),
				}},
			},
		},
		ContainerName: container,
		CgroupID:      cgroupID,
		CgroupPath:    "/sys/fs/cgroup/kubepods/" + pod,
	}
}

func ptr[T any](v T) *T { return &v }

func targetKeys(set tracer.TargetSet) []string {
	out := make([]string, 0, len(set))
	for _, t := range set {
		out = append(out, targetIdentity(t.Namespace, t.PodName, t.ContainerName))
	}
	return out
}

func TestExpansionIsANoOpWhenPlaneDisabled(t *testing.T) {
	entries := []PodCgroupEntry{podEntry("shop", "checkout", "app", 1)}

	got := expandTargetsForMetricsPlane(nil, entries, MetricsPlaneConfig{Enabled: false})
	if len(got) != 0 {
		t.Fatalf("disabled plane added %d targets", len(got))
	}
}

func TestExpansionCoversEveryLocalPodWhenEnabled(t *testing.T) {
	entries := []PodCgroupEntry{
		podEntry("shop", "checkout", "app", 1),
		podEntry("shop", "cart", "app", 2),
		podEntry("infra", "logger", "app", 3),
	}

	got := expandTargetsForMetricsPlane(nil, entries, MetricsPlaneConfig{Enabled: true})
	if len(got) != 3 {
		t.Fatalf("want 3 targets, got %d (%v)", len(got), targetKeys(got))
	}
	for _, want := range []string{"shop/checkout/app", "shop/cart/app", "infra/logger/app"} {
		var found bool
		for _, key := range targetKeys(got) {
			if key == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing target %q", want)
		}
	}
}

func TestExpansionResolvesRolloutStableWorkloadIdentity(t *testing.T) {
	entries := []PodCgroupEntry{
		podEntryOwnedBy("shop", "checkout-7d9f8b6c5d-x4k2p", "checkout-7d9f8b6c5d", "app", 1),
	}

	got := expandTargetsForMetricsPlane(nil, entries, MetricsPlaneConfig{Enabled: true})
	if len(got) != 1 {
		t.Fatalf("want 1 target, got %d", len(got))
	}
	if got[0].OwnerKind != "Deployment" {
		t.Errorf("OwnerKind = %q, want Deployment; a ReplicaSet owner must resolve "+
			"to its Deployment or the identity changes on every rollout", got[0].OwnerKind)
	}
	if got[0].OwnerName != "checkout" {
		t.Errorf("OwnerName = %q, want checkout", got[0].OwnerName)
	}
}

func TestExpansionHonoursNamespaceExclusions(t *testing.T) {
	entries := []PodCgroupEntry{
		podEntry("shop", "checkout", "app", 1),
		podEntry("kube-system", "kube-proxy", "app", 2),
		podEntry("podtrace-system", "podtrace-agent", "app", 3),
	}

	got := expandTargetsForMetricsPlane(nil, entries, MetricsPlaneConfig{
		Enabled:           true,
		ExcludeNamespaces: []string{"kube-system", "podtrace-system"},
	})
	if len(got) != 1 {
		t.Fatalf("want 1 target after exclusions, got %d (%v)", len(got), targetKeys(got))
	}
	if got[0].Namespace != "shop" {
		t.Errorf("kept namespace %q, want shop", got[0].Namespace)
	}
}

func TestExpansionDoesNotDuplicateCRDerivedTargets(t *testing.T) {
	existing := tracer.TargetSet{{
		Namespace:     "shop",
		PodName:       "checkout",
		ContainerName: "app",
	}}
	entries := []PodCgroupEntry{
		podEntry("shop", "checkout", "app", 1),
		podEntry("shop", "cart", "app", 2),
	}

	got := expandTargetsForMetricsPlane(existing, entries, MetricsPlaneConfig{Enabled: true})
	if len(got) != 2 {
		t.Fatalf("want 2 targets, got %d (%v); a pod already covered by a CR "+
			"must not be attached twice", len(got), targetKeys(got))
	}
}

func TestExpansionSkipsEntriesWithoutAPod(t *testing.T) {
	entries := []PodCgroupEntry{{ContainerName: "orphan", CgroupID: 9}}

	got := expandTargetsForMetricsPlane(nil, entries, MetricsPlaneConfig{Enabled: true})
	if len(got) != 0 {
		t.Fatalf("an entry with no pod must not become a target, got %d", len(got))
	}
}

func TestPlaneCategoriesAreUnionedNotSubstituted(t *testing.T) {
	fromRules := []string{"crypto", "usdt"}

	got := unionCategories(fromRules, MetricsPlaneConfig{Enabled: true})

	for _, want := range []string{"crypto", "usdt"} {
		var found bool
		for _, c := range got {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("category %q from a CR was dropped; the plane's set must be "+
				"unioned with what CRs ask for, never substituted", want)
		}
	}
	for _, want := range metricsPlaneCategories() {
		var found bool
		for _, c := range got {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("plane category %q missing from the union", want)
		}
	}
}

func TestPlaneDoesNotEnableCategoriesItCannotConsume(t *testing.T) {
	got := metricsPlaneCategories()
	for _, unwanted := range []string{"proc", "crypto", "usdt"} {
		for _, c := range got {
			if c == unwanted {
				t.Errorf("plane requests category %q, but no metric family consumes it; "+
					"that pays kernel and ringbuf cost for nothing", unwanted)
			}
		}
	}
}

func TestCategoryUnionUntouchedWhenPlaneDisabled(t *testing.T) {
	fromRules := []string{"dns"}

	got := unionCategories(fromRules, MetricsPlaneConfig{Enabled: false})
	if len(got) != 1 || got[0] != "dns" {
		t.Errorf("got %v, want the CR set unchanged when the plane is off", got)
	}
}

func TestPlaneDoesNotEnableFilesystemByDefault(t *testing.T) {
	for _, c := range metricsPlaneCategories() {
		if c == "fs" {
			t.Error("the plane enables `fs` by default. Measured on kind, filesystem " +
				"events were 94.9% of all observations (63185/s on one agent vs 3128/s " +
				"for network) and pinned the agent at its 1-core limit. Filesystem " +
				"latency is a diagnostic signal, not a golden one.")
		}
	}
}

func TestPlaneStillEnablesWhatTheSurfaceConsumes(t *testing.T) {
	got := map[string]bool{}
	for _, c := range metricsPlaneCategories() {
		got[c] = true
	}
	// net carries every L7 protocol as well as the socket families, so
	// dropping it would silently empty the surface's headline metrics.
	for _, want := range []string{"dns", "net"} {
		if !got[want] {
			t.Errorf("category %q missing; the surface has families that consume it", want)
		}
	}
}

func TestFilesystemFamiliesStillPopulateWhenACRAsksForFS(t *testing.T) {
	got := unionCategories([]string{"fs"}, MetricsPlaneConfig{Enabled: true})

	var found bool
	for _, c := range got {
		if c == "fs" {
			found = true
		}
	}
	if !found {
		t.Error("a PodTrace asking for `fs` must still get it with the plane enabled; " +
			"the plane's set is unioned with CR requests, never substituted")
	}
}

func TestStartupCategoriesMatchThePlaneWhenEnabled(t *testing.T) {
	got := StartupCategories(true)
	want := metricsPlaneCategories()

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestStartupCategoriesAreEmptyButNotNilWhenDisabled(t *testing.T) {
	got := StartupCategories(false)

	if got == nil {
		t.Fatal("a nil set tells the tracer not to gate at all, which leaves every " +
			"probe group attached; an agent with the plane off and no CRs collects " +
			"nothing, so it must ask for nothing")
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestStartupCategoriesNeverRequestUngatedWork(t *testing.T) {
	for _, c := range StartupCategories(true) {
		if c == "fs" {
			t.Error("startup set includes fs, which the plane deliberately does not " +
				"measure; gating it in at construction reinstates the cost the " +
				"category set exists to avoid")
		}
	}
}
