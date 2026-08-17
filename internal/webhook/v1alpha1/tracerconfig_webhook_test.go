package v1alpha1

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func tracerConfigValidator(t *testing.T, objs ...client.Object) *TracerConfigCustomValidator {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return &TracerConfigCustomValidator{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
	}
}

func tracerConfig(name string, spec podtracev1alpha1.TracerConfigSpec) *podtracev1alpha1.TracerConfig {
	if spec.Image == "" {
		spec.Image = "ghcr.io/gma1k/podtrace:test"
	}
	return &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
}

func TestTracerConfigRejectsOverlongName(t *testing.T) {
	v := tracerConfigValidator(t)
	long := strings.Repeat("x", podtracev1alpha1.MaxTracerConfigNameLength+1)

	_, err := v.ValidateCreate(context.Background(), tracerConfig(long, podtracev1alpha1.TracerConfigSpec{}))
	if err == nil {
		t.Fatal("expected an over-long name to be rejected")
	}
	if !strings.Contains(err.Error(), "label") {
		t.Errorf("error should explain the label-value limit, got %q", err)
	}
}

func TestTracerConfigAcceptsNameAtTheLimit(t *testing.T) {
	v := tracerConfigValidator(t)
	atLimit := strings.Repeat("x", podtracev1alpha1.MaxTracerConfigNameLength)

	if _, err := v.ValidateCreate(context.Background(), tracerConfig(atLimit, podtracev1alpha1.TracerConfigSpec{})); err != nil {
		t.Errorf("a name exactly at the limit must be accepted, got %v", err)
	}
}

func TestTracerConfigRejectsSecondClusterWideFleet(t *testing.T) {
	existing := tracerConfig("default", podtracev1alpha1.TracerConfigSpec{})
	v := tracerConfigValidator(t, existing)

	_, err := v.ValidateCreate(context.Background(), tracerConfig("second", podtracev1alpha1.TracerConfigSpec{}))
	if err == nil {
		t.Fatal("a second fleet with no node constraints overlaps the first on every node and must be rejected")
	}
	if !strings.Contains(err.Error(), "default") {
		t.Errorf("error should name the conflicting config, got %q", err)
	}
}

func TestTracerConfigAllowsFirstClusterWideFleet(t *testing.T) {
	v := tracerConfigValidator(t)

	if _, err := v.ValidateCreate(context.Background(), tracerConfig("default", podtracev1alpha1.TracerConfigSpec{})); err != nil {
		t.Errorf("the only fleet in a cluster may target every node, got %v", err)
	}
}

func TestTracerConfigAllowsUpdatingAClusterWideFleetInPlace(t *testing.T) {
	existing := tracerConfig("default", podtracev1alpha1.TracerConfigSpec{})
	v := tracerConfigValidator(t, existing)

	updated := tracerConfig("default", podtracev1alpha1.TracerConfigSpec{
		Image: "ghcr.io/gma1k/podtrace:next",
	})
	if _, err := v.ValidateUpdate(context.Background(), existing, updated); err != nil {
		t.Errorf("a config must not conflict with itself, got %v", err)
	}
}

func TestTracerConfigRejectsIdenticalNodeSelector(t *testing.T) {
	existing := tracerConfig("pool-a", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "a"},
	})
	v := tracerConfigValidator(t, existing)

	_, err := v.ValidateCreate(context.Background(), tracerConfig("pool-a-copy", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "a"},
	}))
	if err == nil {
		t.Fatal("two fleets with the same nodeSelector always target the same nodes and must be rejected")
	}
	if !strings.Contains(err.Error(), "pool-a") {
		t.Errorf("error should name the conflicting config, got %q", err)
	}
}

func TestTracerConfigAllowsDisjointNodeSelectors(t *testing.T) {
	existing := tracerConfig("pool-a", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "a"},
	})
	v := tracerConfigValidator(t, existing,
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "a1", Labels: map[string]string{"pool": "a"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "b1", Labels: map[string]string{"pool": "b"}}},
	)

	warnings, err := v.ValidateCreate(context.Background(), tracerConfig("pool-b", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "b"},
	}))
	if err != nil {
		t.Fatalf("disjoint node pools must be accepted, got %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("disjoint fleets must not warn, got %v", warnings)
	}
}

func TestTracerConfigWarnsOnCurrentOverlapWithoutRejecting(t *testing.T) {
	existing := tracerConfig("by-pool", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "a"},
	})
	v := tracerConfigValidator(t, existing,
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name:   "shared",
			Labels: map[string]string{"pool": "a", "zone": "eu-1"},
		}},
	)

	warnings, err := v.ValidateCreate(context.Background(), tracerConfig("by-zone", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"zone": "eu-1"},
	}))
	if err != nil {
		t.Fatalf("overlap that depends on current node labels must warn, not reject, got %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "by-pool") {
		t.Errorf("warning should name the overlapping config, got %q", warnings[0])
	}
}

func TestTracerConfigSkipsValidationWhenSpecUnchanged(t *testing.T) {
	first := tracerConfig("default", podtracev1alpha1.TracerConfigSpec{})
	second := tracerConfig("second", podtracev1alpha1.TracerConfigSpec{})
	v := tracerConfigValidator(t, first)

	warnings, err := v.ValidateUpdate(context.Background(), second, second.DeepCopy())
	if err != nil {
		t.Errorf("a metadata-only update must not re-run spec validation, got %v", err)
	}
	if warnings != nil {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

func TestTracerConfigValidateDeleteIsAlwaysAllowed(t *testing.T) {
	v := tracerConfigValidator(t)

	warnings, err := v.ValidateDelete(context.Background(), tracerConfig("default", podtracev1alpha1.TracerConfigSpec{}))
	if err != nil {
		t.Errorf("deleting a TracerConfig must never be blocked by admission: %v", err)
	}
	if warnings != nil {
		t.Errorf("expected no warnings on delete, got %v", warnings)
	}
}

func TestTracerConfigValidateWithoutClientSkipsClusterChecks(t *testing.T) {
	v := &TracerConfigCustomValidator{}

	if _, err := v.ValidateCreate(context.Background(), tracerConfig("default", podtracev1alpha1.TracerConfigSpec{})); err != nil {
		t.Errorf("with no client the cluster-wide checks must be skipped, not error: %v", err)
	}

	long := strings.Repeat("x", podtracev1alpha1.MaxTracerConfigNameLength+1)
	if _, err := v.ValidateCreate(context.Background(), tracerConfig(long, podtracev1alpha1.TracerConfigSpec{})); err == nil {
		t.Error("the name-length rule needs no client and must still apply")
	}
}

func TestResolveTracerConfigRefWithoutClient(t *testing.T) {
	err := resolveTracerConfigRef(context.Background(), nil, &podtracev1alpha1.LocalObjectReference{Name: "regulated"}, "team-a", "podtrace-system")
	if err == nil {
		t.Fatal("an unconfigured client cannot verify the pin, so it must not silently accept it")
	}
	if !strings.Contains(err.Error(), "TracerConfig") {
		t.Errorf("error should name what could not be resolved, got %q", err)
	}
}

func TestResolveTracerConfigRefNilAndEmptyAreUnset(t *testing.T) {
	if err := resolveTracerConfigRef(context.Background(), nil, nil, "team-a", "podtrace-system"); err != nil {
		t.Errorf("a nil ref means resolve per node, got %v", err)
	}
	if err := resolveTracerConfigRef(context.Background(), nil, &podtracev1alpha1.LocalObjectReference{}, "team-a", "podtrace-system"); err != nil {
		t.Errorf("an empty ref name means resolve per node, got %v", err)
	}
}

func TestTracerConfigRejectsUntrustedImage(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	v := tracerConfigValidator(t)

	_, err := v.ValidateCreate(context.Background(), tracerConfig("default", podtracev1alpha1.TracerConfigSpec{
		Image: "evil.example.com/x:latest",
	}))
	if err == nil {
		t.Fatal("expected an untrusted image to be rejected at admission")
	}
	if !strings.Contains(err.Error(), "not in the operator's allowed set") {
		t.Errorf("error should explain the allowlist, got %q", err)
	}
}

func TestTracerConfigAcceptsTrustedImage(t *testing.T) {
	t.Setenv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS", "ghcr.io/gma1k/podtrace")
	v := tracerConfigValidator(t)

	if _, err := v.ValidateCreate(context.Background(), tracerConfig("default", podtracev1alpha1.TracerConfigSpec{
		Image: "ghcr.io/gma1k/podtrace:0.14.3",
	})); err != nil {
		t.Errorf("trusted image must be admitted, got %v", err)
	}
}
