package operator

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestReconcile_RejectsUntrustedImage_NoDaemonSet(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")

	c, r := reconcileFleets(t, []client.Object{
		fleetConfig("default", podtracev1alpha1.TracerConfigSpec{Image: "evil.example.com/x:latest"}),
	}, "default")

	var ds appsv1.DaemonSet
	err := c.Get(context.Background(), types.NamespacedName{
		Name: AgentDaemonSetName("default"), Namespace: r.SystemNamespace,
	}, &ds)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("agent DaemonSet must not be created for an untrusted image; got err=%v", err)
	}

	var tc podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, &tc); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindStatusCondition(tc.Status.Conditions, ConditionReady)
	if ready == nil || ready.Status != "False" || ready.Reason != "ImageNotAllowed" {
		t.Fatalf("expected Ready=False reason=ImageNotAllowed, got %+v", ready)
	}
}

func TestReconcile_AcceptsTrustedImage_CreatesDaemonSet(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")

	c, r := reconcileFleets(t, []client.Object{
		fleetConfig("default", podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:0.14.3"}),
	}, "default")

	var ds appsv1.DaemonSet
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: AgentDaemonSetName("default"), Namespace: r.SystemNamespace,
	}, &ds); err != nil {
		t.Fatalf("agent DaemonSet must be created for a trusted image: %v", err)
	}
}

func TestReconcile_AllowsMirrorRepoViaEnv(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace,registry.internal:5000/mirror")

	c, r := reconcileFleets(t, []client.Object{
		fleetConfig("default", podtracev1alpha1.TracerConfigSpec{Image: "registry.internal:5000/mirror/podtrace:0.14.3"}),
	}, "default")

	var ds appsv1.DaemonSet
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: AgentDaemonSetName("default"), Namespace: r.SystemNamespace,
	}, &ds); err != nil {
		t.Fatalf("agent DaemonSet must be created for an admin-allowed mirror image: %v", err)
	}
}

func TestReconcile_RecoversWhenImageCorrected(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")

	c, r := reconcileFleets(t, []client.Object{
		fleetConfig("default", podtracev1alpha1.TracerConfigSpec{Image: "evil.example.com/x:latest"}),
	}, "default")

	var tc podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, &tc); err != nil {
		t.Fatal(err)
	}
	tc.Spec.Image = "ghcr.io/gma1k/podtrace:0.14.3"
	if err := c.Update(context.Background(), &tc); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	}); err != nil {
		t.Fatalf("reconcile after correcting image: %v", err)
	}

	var ds appsv1.DaemonSet
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: AgentDaemonSetName("default"), Namespace: r.SystemNamespace,
	}, &ds); err != nil {
		t.Fatalf("DaemonSet must be created once the image is corrected to a trusted repo: %v", err)
	}
}
