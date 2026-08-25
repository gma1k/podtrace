package v1alpha1

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func errServerTimeout() error {
	return apierrors.NewServerTimeout(schema.GroupResource{Resource: "podtrace"}, "get", 1)
}

func interceptedClient(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	s := clientgoscheme.Scheme
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}

func TestResolveTracerConfigRefSurfacesNonNotFoundErrors(t *testing.T) {
	c := interceptedClient(t, interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			if _, ok := obj.(*podtracev1alpha1.TracerConfig); ok {
				return errServerTimeout()
			}
			return nil
		},
	})

	err := resolveTracerConfigRef(context.Background(), c, &corev1.LocalObjectReference{Name: "regulated"}, "team-a", "podtrace-system")
	if err == nil {
		t.Fatal("an apiserver failure must not be mistaken for a missing TracerConfig")
	}
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("a transient error must not be reported as not-found, got %q", err)
	}
}

func TestResolveExporterRefSurfacesNonNotFoundErrors(t *testing.T) {
	c := interceptedClient(t, interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			if _, ok := obj.(*podtracev1alpha1.ExporterConfig); ok {
				return errServerTimeout()
			}
			return nil
		},
	})

	err := resolveExporterRef(context.Background(), c, "default", "prod-otlp")
	if err == nil {
		t.Fatal("an apiserver failure must not be mistaken for a missing ExporterConfig")
	}
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("a transient error must not be reported as not-found, got %q", err)
	}
}

func TestTracerConfigValidateSurfacesListFailure(t *testing.T) {
	c := interceptedClient(t, interceptor.Funcs{
		List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
			if _, ok := list.(*podtracev1alpha1.TracerConfigList); ok {
				return errServerTimeout()
			}
			return nil
		},
	})
	v := &TracerConfigCustomValidator{Client: c}

	_, err := v.ValidateCreate(context.Background(), tracerConfig("regulated", podtracev1alpha1.TracerConfigSpec{}))
	if err == nil {
		t.Fatal("admission cannot judge overlap without the config list, so the failure must surface")
	}
	if !strings.Contains(err.Error(), "fleet overlap") {
		t.Errorf("error should explain what could not be checked, got %q", err)
	}
}

func TestWarnOnCurrentOverlapStaysSilentWhenNodesUnreadable(t *testing.T) {
	existing := tracerConfig("default", podtracev1alpha1.TracerConfigSpec{})
	c := interceptedClient(t, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.NodeList); ok {
				return errServerTimeout()
			}
			return cl.List(ctx, list, opts...)
		},
	}, existing)
	v := &TracerConfigCustomValidator{Client: c}

	warnings, err := v.ValidateCreate(context.Background(), tracerConfig("regulated", podtracev1alpha1.TracerConfigSpec{
		NodeSelector: map[string]string{"pool": "regulated"},
	}))
	if err != nil {
		t.Fatalf("unreadable nodes must not block admission; the operator reports overlap anyway: %v", err)
	}
	if warnings != nil {
		t.Errorf("no node list means no basis for a warning, got %v", warnings)
	}
}

func TestValidateCrossNamespaceGrantsIgnoresInvalidSelector(t *testing.T) {
	c := interceptedClient(t, interceptor.Funcs{})

	warnings, err := validateCrossNamespaceGrants(context.Background(), c, "team-a", nil,
		&metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "BOGUS"}}})
	if err != nil {
		t.Errorf("an unparseable selector is rejected by the dedicated selector rule, not here: %v", err)
	}
	if warnings != nil {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

func TestValidateCrossNamespaceGrantsSkipsTerminatingNamespaces(t *testing.T) {
	now := metav1.Now()
	terminating := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:              "going-away",
		Labels:            map[string]string{"team": "obs"},
		DeletionTimestamp: &now,
		Finalizers:        []string{"kubernetes"},
	}}
	c := interceptedClient(t, interceptor.Funcs{}, terminating)

	warnings, err := validateCrossNamespaceGrants(context.Background(), c, "team-a", nil,
		&metav1.LabelSelector{MatchLabels: map[string]string{"team": "obs"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warnings != nil {
		t.Errorf("a terminating namespace will never be traced, so it must not be reported as ungranted, got %v", warnings)
	}
}

func TestValidateReportRefCountsSecretSink(t *testing.T) {
	err := validateReportRef(&podtracev1alpha1.ReportReference{
		Secret:    &corev1.LocalObjectReference{Name: "rpt"},
		ConfigMap: &corev1.LocalObjectReference{Name: "rpt"},
	})
	if err == nil {
		t.Fatal("a Secret sink must count toward the at-most-one-sink rule")
	}

	if err := validateReportRef(&podtracev1alpha1.ReportReference{
		Secret: &corev1.LocalObjectReference{Name: "rpt"},
	}); err != nil {
		t.Errorf("a lone Secret sink is valid, got %v", err)
	}
}

func scheduleWithTemplate(mutate func(*podtracev1alpha1.PodTraceSessionSpec)) *podtracev1alpha1.PodTraceSchedule {
	spec := podtracev1alpha1.PodTraceSessionSpec{
		Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
		Duration:    metav1.Duration{Duration: 60000000000},
		ExporterRef: corev1.LocalObjectReference{Name: "prod-otlp"},
	}
	mutate(&spec)
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "sch", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule:        "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{Spec: spec},
		},
	}
}

func TestScheduleTemplateRejectsInvalidNamespaceSelector(t *testing.T) {
	c := interceptedClient(t, interceptor.Funcs{},
		&podtracev1alpha1.ExporterConfig{ObjectMeta: metav1.ObjectMeta{Name: "prod-otlp", Namespace: "default"}})
	v := &PodTraceScheduleCustomValidator{Client: c}

	sch := scheduleWithTemplate(func(s *podtracev1alpha1.PodTraceSessionSpec) {
		s.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "BOGUS"}},
		}
	})

	_, err := v.ValidateCreate(context.Background(), sch)
	if err == nil {
		t.Fatal("an unparseable namespaceSelector inside the template must be rejected before it spawns sessions")
	}
	if !strings.Contains(err.Error(), "sessionTemplate") {
		t.Errorf("error should point at the template, got %q", err)
	}
}

func TestScheduleTemplateRejectsInvalidReportRef(t *testing.T) {
	c := interceptedClient(t, interceptor.Funcs{},
		&podtracev1alpha1.ExporterConfig{ObjectMeta: metav1.ObjectMeta{Name: "prod-otlp", Namespace: "default"}})
	v := &PodTraceScheduleCustomValidator{Client: c}

	sch := scheduleWithTemplate(func(s *podtracev1alpha1.PodTraceSessionSpec) {
		s.ReportRef = &podtracev1alpha1.ReportReference{
			ConfigMap: &corev1.LocalObjectReference{Name: "rpt"},
			Secret:    &corev1.LocalObjectReference{Name: "rpt"},
		}
	})

	_, err := v.ValidateCreate(context.Background(), sch)
	if err == nil {
		t.Fatal("two report sinks in the template must be rejected, same as on a session")
	}
	if !strings.Contains(err.Error(), "sessionTemplate") {
		t.Errorf("error should point at the template, got %q", err)
	}
}
