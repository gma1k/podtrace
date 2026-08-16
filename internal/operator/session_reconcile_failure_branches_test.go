package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestEnsureJobs_UnresolvedNodeErrors(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "u-ghost"},
	}
	targets := sessionTargets{Nodes: []string{"ghost-node"}}
	resolved := resolvedFleet(r.SystemNamespace, nil, testTracerConfig("default", "img:test", "", nil))

	if _, err := r.ensureJobs(context.Background(), s, resolved, targets, nil); err == nil {
		t.Fatal("expected error when a target node has no resolved TracerConfig")
	}
}

func TestSessionReconcile_BundleSyncErrorRequeues(t *testing.T) {
	scheme := newOperatorScheme(t)
	objs := append(sessMoreFanOutObjects(), sessMoreSession(nil))
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Namespace == sessMoreSysNS {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	res, err := sessMoreReconcile(t, r)
	if err != nil || res.RequeueAfter != 60*time.Second {
		t.Fatalf("bundle-sync failure: res=%+v err=%v, want RequeueAfter=60s nil", res, err)
	}
}

func TestSessionReconcile_FinalStatusUpdateErrorPropagates(t *testing.T) {
	scheme := newOperatorScheme(t)
	objs := append(sessMoreFanOutObjects(), sessMoreSession(nil))
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("expected the final status update error to propagate")
	}
}

func TestSessionReconcile_ExporterConfigNameTooLongFailsTerminally(t *testing.T) {
	scheme := newOperatorScheme(t)
	longEC := strings.Repeat("e", 64)
	objs := []client.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default", Labels: map[string]string{"a": "b"}},
			Spec:       corev1.PodSpec{NodeName: "n1"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&podtracev1alpha1.ExporterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: longEC, Namespace: "default"},
			Spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
			},
		},
		&podtracev1alpha1.TracerConfig{
			ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName},
			Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
		},
		sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.Spec.ExporterRef.Name = longEC }),
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	res, err := sessMoreReconcile(t, r)
	if err != nil || res.RequeueAfter != 0 {
		t.Fatalf("ExporterConfig-name-too-long: res=%+v err=%v, want terminal (no requeue)", res, err)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "s"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Fatalf("state = %q, want Failed", got.Status.State)
	}
}
