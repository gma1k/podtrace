package operator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func resolvedFleet(fallbackNS string, nodes []string, tc *podtracev1alpha1.TracerConfig) sessionTracerConfigs {
	byNode := map[string]*podtracev1alpha1.TracerConfig{}
	for _, n := range nodes {
		byNode[n] = tc
	}
	return sessionTracerConfigs{byNode: byNode, namespaces: distinctNamespaces(byNode, fallbackNS)}
}

func testTracerConfig(name, image, systemNS string, nodeSelector map[string]string) *podtracev1alpha1.TracerConfig {
	return &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:           image,
			SystemNamespace: systemNS,
			NodeSelector:    nodeSelector,
		},
	}
}

func sessionResolver(t *testing.T, objs ...client.Object) *PodTraceSessionReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	return &PodTraceSessionReconciler{
		Client:          fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
		Scheme:          scheme,
		SystemNamespace: "podtrace-system",
	}
}

func sessionWithRef(name string) *podtracev1alpha1.PodTraceSession {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a", UID: "uid-s"},
	}
	if name != "" {
		s.Spec.TracerConfigRef = &corev1.LocalObjectReference{Name: name}
	}
	return s
}

func TestSessionResolvesPerNodeFleet(t *testing.T) {
	r := sessionResolver(t,
		testTracerConfig("default", "img:default", "", nil),
		testTracerConfig("regulated", "img:regulated", "", map[string]string{"pool": "regulated"}),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n-general", Labels: map[string]string{"pool": "general"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n-regulated", Labels: map[string]string{"pool": "regulated"}}},
	)

	got, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n-general", "n-regulated"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if name := got.forNode("n-regulated").Name; name != "regulated" {
		t.Errorf("n-regulated resolved to %q, want regulated", name)
	}
	if name := got.forNode("n-general").Name; name != "default" {
		t.Errorf("n-general resolved to %q, want default", name)
	}
}

func TestSessionRefPinsEveryNode(t *testing.T) {
	r := sessionResolver(t,
		testTracerConfig("default", "img:default", "", nil),
		testTracerConfig("regulated", "img:regulated", "", map[string]string{"pool": "regulated"}),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n-regulated", Labels: map[string]string{"pool": "regulated"}}},
	)

	got, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef("default"), []string{"n-regulated"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if name := got.forNode("n-regulated").Name; name != "default" {
		t.Errorf("an explicit tracerConfigRef must override the node's fleet, got %q", name)
	}
}

func TestSessionRefNotFoundIsTerminal(t *testing.T) {
	r := sessionResolver(t, testTracerConfig("default", "img:default", "", nil))

	_, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef("ghost"), []string{"n1"})
	var missing *errNoTracerConfig
	if !errors.As(err, &missing) {
		t.Fatalf("want errNoTracerConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should name the missing config, got %q", err)
	}
}

func TestSessionFallsBackToDefaultWhenNoFleetMatches(t *testing.T) {
	r := sessionResolver(t,
		testTracerConfig("default", "img:default", "", nil),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
	)

	got, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n1"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if name := got.forNode("n1").Name; name != "default" {
		t.Errorf("resolved %q, want default", name)
	}
}

func TestSessionWithNoTracerConfigAtAllErrors(t *testing.T) {
	r := sessionResolver(t, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}})

	_, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n1"})
	var missing *errNoTracerConfig
	if !errors.As(err, &missing) {
		t.Fatalf("a session with no resolvable TracerConfig must error rather than build an image-less Job, got %v", err)
	}
	if !strings.Contains(err.Error(), "no TracerConfig") {
		t.Errorf("error should explain the cause, got %q", err)
	}
}

func TestSessionCollectsDistinctSystemNamespaces(t *testing.T) {
	r := sessionResolver(t,
		testTracerConfig("default", "img:default", "ns-a", nil),
		testTracerConfig("regulated", "img:regulated", "ns-b", map[string]string{"pool": "regulated"}),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n-general", Labels: map[string]string{"pool": "general"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n-regulated", Labels: map[string]string{"pool": "regulated"}}},
	)

	got, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n-general", "n-regulated"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got.namespaces) != 2 || got.namespaces[0] != "ns-a" || got.namespaces[1] != "ns-b" {
		t.Errorf("namespaces = %v, want [ns-a ns-b] so prerequisites are provisioned in both", got.namespaces)
	}
	if ns := got.namespaceForNode("n-regulated", "fallback"); ns != "ns-b" {
		t.Errorf("n-regulated Job namespace = %q, want ns-b", ns)
	}
}

func TestSessionPrimaryIsDeterministic(t *testing.T) {
	r := sessionResolver(t,
		testTracerConfig("default", "img:default", "", nil),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
	)

	first, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n2", "n1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n1", "n2"})
	if err != nil {
		t.Fatal(err)
	}
	if first.primary().Name != second.primary().Name {
		t.Errorf("primary must not depend on node order: %q vs %q", first.primary().Name, second.primary().Name)
	}
}

func TestSessionContestedNodeUsesPartitionWinner(t *testing.T) {
	low := testTracerConfig("low", "img:low", "", nil)
	high := testTracerConfig("high", "img:high", "", nil)
	high.Spec.FleetPriority = 10

	r := sessionResolver(t, low, high,
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
	)

	got, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n1"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if name := got.forNode("n1").Name; name != "high" {
		t.Errorf("contested node resolved to %q, want the partition winner high", name)
	}
}

func defaultTracerConfigObject() *podtracev1alpha1.TracerConfig {
	return testTracerConfig(DefaultTracerConfigName, "ghcr.io/gma1k/podtrace:test", "", nil)
}

func TestSessionRefSurfacesNonNotFoundGetError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.TracerConfig); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	_, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef("regulated"), []string{"n1"})
	if err == nil {
		t.Fatal("an apiserver failure must propagate rather than be treated as unresolvable")
	}
	var missing *errNoTracerConfig
	if errors.As(err, &missing) {
		t.Error("a transient failure must not fail the session terminally; it should be retried")
	}
}

func TestSessionResolutionSurfacesListFailure(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.TracerConfigList); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	_, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef(""), []string{"n1"})
	if err == nil {
		t.Fatal("without the config list there is no basis to resolve, so the failure must surface")
	}
	var missing *errNoTracerConfig
	if errors.As(err, &missing) {
		t.Error("an unreadable list is transient, not a terminal misconfiguration")
	}
}
