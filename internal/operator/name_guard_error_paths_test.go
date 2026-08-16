package operator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

func TestSessionJobName_EmptyNodeFallsBackToPrefixAndSuffix(t *testing.T) {
	got := SessionJobName(types.UID("abcdef012345"), "!!!")
	if !strings.HasPrefix(got, "pts-") || len(got) == 0 {
		t.Fatalf("SessionJobName with unsanitisable node = %q, want pts-<uid><suffix>", got)
	}
}

func longNameExporterConfig(name string) *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo", Generation: 1},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "http://collector:4318"},
		},
	}
}

func TestExporterConfigReconciler_TooLongNameIsIdempotent(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("e", 64)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(longNameExporterConfig(name)).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	res, err := r.Reconcile(context.Background(), req)
	if err != nil || res.RequeueAfter != 0 {
		t.Fatalf("second reconcile (status unchanged) res=%+v err=%v, want no-op", res, err)
	}
}

func TestExporterConfigReconciler_TooLongNamePatchConflictRequeues(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("e", 64)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(longNameExporterConfig(name)).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
				return apierrors.NewConflict(schema.GroupResource{Group: "podtrace.io", Resource: "exporterconfigs"}, name, errors.New("conflict"))
			},
		}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}})
	if err != nil || res.RequeueAfter != time.Second {
		t.Fatalf("conflict path res=%+v err=%v, want RequeueAfter=1s nil", res, err)
	}
}

func TestExporterConfigReconciler_TooLongNamePatchErrorPropagates(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("e", 64)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(longNameExporterConfig(name)).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
				return errors.New("boom")
			},
		}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}}); err == nil {
		t.Fatal("expected patch error to propagate")
	}
}

func TestApplicationTraceReconciler_TooLongNameStatusWriteErrorPropagates(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("a", 64)
	app := &podtracev1alpha1.ApplicationTrace{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(app).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
				return errors.New("boom")
			},
		}).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "demo", Name: name}}); err == nil {
		t.Fatal("expected patchStatus error to propagate")
	}
}

func TestTracerConfigReconciler_InvalidNameStatusWriteErrorPropagates(t *testing.T) {
	scheme := newOperatorScheme(t)
	name := strings.Repeat("t", 64)
	tc := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: name}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
				return errors.New("boom")
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err == nil {
		t.Fatal("expected InvalidName status-update error to propagate")
	}
}
