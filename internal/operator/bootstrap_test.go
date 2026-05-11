package operator

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func bootstrapTestScheme(t *testing.T) client.WithWatch {
	t.Helper()
	scheme, err := NewScheme()
	if err != nil {
		t.Fatalf("scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).Build()
}

func TestBootstrap_NeedLeaderElection(t *testing.T) {
	b := &BootstrapDefaultTracerConfig{}
	if !b.NeedLeaderElection() {
		t.Fatal("BootstrapDefaultTracerConfig must opt into leader election")
	}
}

func TestBootstrap_CreatesDefaultWhenAbsent(t *testing.T) {
	c := bootstrapTestScheme(t)
	b := &BootstrapDefaultTracerConfig{
		Client:          c,
		SystemNamespace: "podtrace-system",
		FallbackImage:   "ghcr.io/gma1k/podtrace:test",
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatalf("get TracerConfig %q: %v", DefaultTracerConfigName, err)
	}
	if got.Spec.Image != "ghcr.io/gma1k/podtrace:test" {
		t.Errorf("Spec.Image = %q, want fallback image", got.Spec.Image)
	}
	if got.Annotations["podtrace.io/bootstrap-source"] != "operator" {
		t.Errorf("missing bootstrap-source annotation; got %v", got.Annotations)
	}
}

func TestBootstrap_NoopWhenTracerConfigExists(t *testing.T) {
	c := bootstrapTestScheme(t)

	preExisting := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "user-supplied:v1"},
	}
	if err := c.Create(context.Background(), preExisting); err != nil {
		t.Fatalf("seed: %v", err)
	}

	b := &BootstrapDefaultTracerConfig{
		Client:          c,
		SystemNamespace: "podtrace-system",
		FallbackImage:   "should-not-be-used:v0",
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Image != "user-supplied:v1" {
		t.Errorf("bootstrap clobbered existing TracerConfig: got Image=%q, want user-supplied:v1",
			got.Spec.Image)
	}
}

func TestBootstrap_NoopWhenAnyTracerConfigExists(t *testing.T) {
	c := bootstrapTestScheme(t)

	custom := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "production"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "prod:v9"},
	}
	if err := c.Create(context.Background(), custom); err != nil {
		t.Fatalf("seed: %v", err)
	}

	b := &BootstrapDefaultTracerConfig{
		Client:        c,
		FallbackImage: "should-not-be-used:v0",
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var nope podtracev1alpha1.TracerConfig
	err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &nope)
	if err == nil {
		t.Fatal("operator created a 'default' TracerConfig despite an existing 'production' one")
	}
}

func TestBootstrap_SkipsWhenNoImageConfigured(t *testing.T) {
	t.Setenv(BootstrapImageEnv, "")
	c := bootstrapTestScheme(t)
	b := &BootstrapDefaultTracerConfig{
		Client: c,
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var got podtracev1alpha1.TracerConfig
	err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got)
	if err == nil {
		t.Fatal("bootstrap created a TracerConfig with no image; should have skipped")
	}
}

func TestBootstrap_EnvVarTakesPrecedence(t *testing.T) {
	t.Setenv(BootstrapImageEnv, "olm-injected:v2")
	c := bootstrapTestScheme(t)
	b := &BootstrapDefaultTracerConfig{
		Client:        c,
		FallbackImage: "should-not-be-used:v0",
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Image != "olm-injected:v2" {
		t.Errorf("env var ignored: got Image=%q, want olm-injected:v2", got.Spec.Image)
	}
}