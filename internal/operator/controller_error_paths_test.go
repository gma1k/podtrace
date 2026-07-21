package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func ecWithSecretRef() *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint:          "otel:4317",
				Protocol:          podtracev1alpha1.OTLPProtocolHTTP,
				HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "creds"},
			},
		},
	}
}

func TestEC_EvaluateReadiness_TransientSecretError(t *testing.T) {
	scheme := newOperatorScheme(t)
	ec := ecWithSecretRef()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}
	ready, status, reason, _ := r.evaluateReadiness(context.Background(), ec)
	if ready {
		t.Error("transient secret error must not be Ready")
	}
	if status != metav1.ConditionUnknown || reason != ecReasonTransientError {
		t.Errorf("got status=%v reason=%q, want Unknown/%s", status, reason, ecReasonTransientError)
	}
}

func TestEC_CountReferences_SessionListError(t *testing.T) {
	scheme := newOperatorScheme(t)
	ec := ecWithSecretRef()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).
		WithIndex(&podtracev1alpha1.PodTrace{}, IndexFieldPodTraceExporterRef,
			func(o client.Object) []string {
				pt := o.(*podtracev1alpha1.PodTrace)
				if pt.Spec.ExporterRef.Name == "" {
					return nil
				}
				return []string{pt.Spec.ExporterRef.Name}
			}).
		WithIndex(&podtracev1alpha1.PodTraceSession{}, IndexFieldPodTraceSessionExporterRef,
			func(o client.Object) []string {
				pts := o.(*podtracev1alpha1.PodTraceSession)
				if pts.Spec.ExporterRef.Name == "" {
					return nil
				}
				return []string{pts.Spec.ExporterRef.Name}
			}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.PodTraceSessionList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}
	if _, err := r.countReferences(context.Background(), ec); err == nil {
		t.Fatal("expected PodTraceSession list error to propagate")
	}
}

func TestEC_CountReferences_PodTraceListError(t *testing.T) {
	scheme := newOperatorScheme(t)
	ec := ecWithSecretRef()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).
		WithIndex(&podtracev1alpha1.PodTrace{}, IndexFieldPodTraceExporterRef,
			func(o client.Object) []string {
				pt := o.(*podtracev1alpha1.PodTrace)
				if pt.Spec.ExporterRef.Name == "" {
					return nil
				}
				return []string{pt.Spec.ExporterRef.Name}
			}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.PodTraceList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}
	if _, err := r.countReferences(context.Background(), ec); err == nil {
		t.Fatal("expected PodTrace list error to propagate")
	}
}

func TestEC_SecretToExporterConfigs_ListError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errInternal()
			},
		}).Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}
	got := r.secretToExporterConfigs(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "team-a"},
	})
	if got != nil {
		t.Errorf("secretToExporterConfigs on List error = %v, want nil", got)
	}
}

func TestApplicationTrace_PatchStatus_NotFoundReturnsNil(t *testing.T) {
	scheme := newOperatorScheme(t)

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}
	app := &podtracev1alpha1.ApplicationTrace{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"}}
	if err := r.patchStatus(context.Background(), app); err != nil {
		t.Fatalf("patchStatus for missing object must return nil, got %v", err)
	}
}

func TestApplicationTrace_PatchStatus_GenericError(t *testing.T) {
	scheme := newOperatorScheme(t)
	app := &podtracev1alpha1.ApplicationTrace{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}).
		WithObjects(app).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: scheme}
	if err := r.patchStatus(context.Background(), app); err == nil {
		t.Fatal("expected patchStatus to surface a non-conflict status error")
	}
}

func TestCleanupOrphanBundles_SecretDeleteError(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := &podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "team-a", UID: "u"}}
	orphanSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      "bundle",
		Namespace: "old-sys",
		Labels: map[string]string{
			LabelManagedBy:    ManagedByValue,
			LabelComponent:    ComponentBundle,
			LabelPodTraceName: pt.Name,
			LabelPodTraceNS:   pt.Namespace,
		},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphanSecret).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()

	if err := cleanupOrphanBundles(context.Background(), c, pt, "new-sys"); err == nil {
		t.Fatal("expected orphan Secret delete error to propagate")
	}
}

func TestCleanupPodTraceSessionChildren_JobListError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a", UID: "u"}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				return errInternal()
			},
		}).Build()
	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, "podtrace-system"); err == nil {
		t.Fatal("expected Job list error to propagate")
	}
}
