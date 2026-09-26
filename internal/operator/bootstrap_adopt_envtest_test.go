//go:build envtest
// +build envtest

package operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func clientAs(t *testing.T, userAgent string) client.Client {
	t.Helper()
	cfg := rest.CopyConfig(testEnv.Config)
	cfg.UserAgent = userAgent
	c, err := client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		t.Fatalf("client as %s: %v", userAgent, err)
	}
	return c
}

func TestEnvtest_AnUpgradeKeepsTheBootstrappedTracerConfigCurrentButNotTheUsersEdits(t *testing.T) {
	setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := "bootstrap-upgrade-probe"
	oldOperator := clientAs(t, "podtrace/v0.14.8")
	user := clientAs(t, "kubectl-edit/v1.37")

	legacy := NewBootstrapTracerConfig(name, "ghcr.io/gma1k/podtrace:0.14.8", "")
	delete(legacy.Annotations, bootstrapFieldsAnnotation)
	legacy.Spec.Tolerations = nil
	if err := oldOperator.Create(ctx, legacy); err != nil {
		t.Fatalf("create as the old operator: %v", err)
	}
	t.Cleanup(func() { _ = testClient.Delete(context.Background(), legacy) })

	var stored podtracev1alpha1.TracerConfig
	if err := user.Get(ctx, types.NamespacedName{Name: name}, &stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	patch := client.MergeFrom(stored.DeepCopy())
	stored.Spec.Session.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("2Gi")
	if err := user.Patch(ctx, &stored, patch); err != nil {
		t.Fatalf("patch as the user: %v", err)
	}

	b := &BootstrapDefaultTracerConfig{
		Client:           clientAs(t, "podtrace/v0.15.0"),
		SystemNamespace:  "podtrace-system",
		FallbackImage:    "ghcr.io/gma1k/podtrace:0.15.0",
		TracerConfigName: name,
	}
	if err := b.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var got podtracev1alpha1.TracerConfig
	if err := testClient.Get(ctx, types.NamespacedName{Name: name}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Spec.Image != "ghcr.io/gma1k/podtrace:0.15.0" {
		t.Errorf("image = %s; the agents would stay on the version the first operator installed", got.Spec.Image)
	}
	if len(got.Spec.Tolerations) == 0 {
		t.Error("no tolerations; the control-plane node would stay without an agent after the upgrade")
	}
	if ns := excludeNamespacesOf(&got); len(ns) != 1 || ns[0] != "podtrace-system" {
		t.Errorf("excludeNamespaces = %v, want podtrace-system", ns)
	}
	if mem := got.Spec.Session.Resources.Limits[corev1.ResourceMemory]; mem.Cmp(resource.MustParse("2Gi")) != 0 {
		t.Errorf("session memory limit = %s; the user's 2Gi edit was overwritten", mem.String())
	}
	if !got.Spec.Agent.Metrics.MetricsEnabled() {
		t.Error("the metrics plane is off on the upgraded object")
	}

	generation := got.Generation
	if err := b.Start(ctx); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if err := testClient.Get(ctx, types.NamespacedName{Name: name}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Generation != generation {
		t.Errorf("generation %d -> %d on a restart with nothing to change; every operator restart "+
			"would roll the agents", generation, got.Generation)
	}
}
