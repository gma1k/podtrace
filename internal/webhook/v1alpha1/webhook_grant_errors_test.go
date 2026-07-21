package v1alpha1_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/podtrace/podtrace/internal/webhook/v1alpha1"
)

func webhookScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	return s
}

func exporterObject(namespace, name string) *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "x:4318"},
		},
	}
}

func TestPodTraceSessionValidator_NilClientReportsMisconfiguration(t *testing.T) {
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: nil}
	obj := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs:     []podtracev1alpha1.PodRef{{Name: "pod"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil || !strings.Contains(err.Error(), "webhook client not configured") {
		t.Fatalf("expected client-not-configured error, got %v", err)
	}
}

func TestPodTraceSessionValidator_DeduplicatesGrantChecksAcrossRefs(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp", grantNS("team-b", "default"))
	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}
	obj := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs: []podtracev1alpha1.PodRef{
				{Namespace: "team-b", Name: "pod-1"},
				{Namespace: "team-b", Name: "pod-2"},
			},
			Duration:    metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
		t.Fatalf("two refs to the same granted namespace must pass: %v", err)
	}
}

func TestPodTraceSessionValidator_NamespaceGetErrorPropagates(t *testing.T) {
	scheme := webhookScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(exporterObject("default", "prod-otlp")).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok {
					return errors.New("apiserver unavailable")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()

	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}
	obj := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs:     []podtracev1alpha1.PodRef{{Namespace: "team-b", Name: "victim"}},
			Duration:    metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil || !strings.Contains(err.Error(), "check namespace") {
		t.Fatalf("expected namespace grant-check error to propagate, got %v", err)
	}
}

func TestPodTraceSessionValidator_NamespaceListErrorPropagates(t *testing.T) {
	scheme := webhookScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(exporterObject("default", "prod-otlp")).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.NamespaceList); ok {
					return errors.New("apiserver list unavailable")
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()

	v := &webhookv1alpha1.PodTraceSessionCustomValidator{Client: c}
	obj := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}},
			Duration:          metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil || !strings.Contains(err.Error(), "list namespaces") {
		t.Fatalf("expected namespace-list error to propagate, got %v", err)
	}
}
