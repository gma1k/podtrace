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

func narrowingTrace() *podtracev1alpha1.PodTrace {
	return ptMoreTrace(func(pt *podtracev1alpha1.PodTrace) {
		pt.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "b"}}
	})
}

func exporterWithMissingCredential() *podtracev1alpha1.ExporterConfig {
	ec := ptMoreExporterConfig()
	ec.Spec.OTLP.Headers = []podtracev1alpha1.OTLPHeader{{
		Name:      "Authorization",
		ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "deleted-by-tenant", Key: "token"},
	}}
	return ec
}

func tenantNamespace(grant string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b", Labels: map[string]string{"team": "b"}}}
	if grant != "" {
		ns.Annotations = map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: grant}
	}
	return ns
}

func policyAppliedReason(t *testing.T, c client.Client) string {
	t.Helper()
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	for _, cond := range got.Status.Conditions {
		if cond.Type == ConditionPolicyApplied {
			return cond.Reason + ": " + cond.Message
		}
	}
	return ""
}

func reconciledCondition(t *testing.T, c client.Client) string {
	t.Helper()
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionReconciled)
	if cond == nil {
		return ""
	}
	return string(cond.Status) + "/" + cond.Reason
}

func TestPodTraceReconcile_UnreadableCredentialStillWithdrawsRevokedNamespace(t *testing.T) {
	pt := narrowingTrace()
	objects := append([]client.Object{pt, exporterWithMissingCredential(), tenantNamespace("")}, existingBundle(pt, ptMoreSysNS)...)
	r := newWithdrawalReconciler(t, objects...)

	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if left := bundleObjectsLeft(t, r.Client); left != 0 {
		t.Fatalf("a bundle still targeting a namespace that withdrew its grant must be withdrawn even when the credential cannot be read; %d object(s) left", left)
	}
	if reason := policyAppliedReason(t, r.Client); !strings.HasPrefix(reason, "BundleSync: exporter bundle withdrawn") {
		t.Errorf("PolicyApplied = %q, want the BundleSync withdrawal", reason)
	}
	if got := reconciledCondition(t, r.Client); got != "False/BundleSync" {
		t.Errorf("Reconciled = %s, want False/BundleSync once the bundle is withdrawn", got)
	}
	var got podtracev1alpha1.PodTrace
	if err := r.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	for _, cond := range got.Status.Conditions {
		if cond.Type == ConditionDegraded && !strings.Contains(cond.Message, "[tenant-b]") {
			t.Errorf("Degraded message %q must name the namespace that withdrew", cond.Message)
		}
	}
}

func TestPodTraceReconcile_UnreadableCredentialKeepsBundleWhileGrantHolds(t *testing.T) {
	cases := map[string]func(pt *podtracev1alpha1.PodTrace) []client.Object{
		"grant still present": func(pt *podtracev1alpha1.PodTrace) []client.Object {
			return append([]client.Object{tenantNamespace("default")}, existingBundle(pt, ptMoreSysNS)...)
		},
		"bundle without target namespaces": func(pt *podtracev1alpha1.PodTrace) []client.Object {
			objects := existingBundle(pt, ptMoreSysNS)
			objects[0].(*corev1.ConfigMap).Data = map[string]string{}
			return append([]client.Object{tenantNamespace("")}, objects...)
		},
		"no bundle written yet": func(*podtracev1alpha1.PodTrace) []client.Object {
			return []client.Object{tenantNamespace("")}
		},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			pt := narrowingTrace()
			before := extra(pt)
			r := newWithdrawalReconciler(t, append([]client.Object{pt, exporterWithMissingCredential()}, before...)...)
			want := bundleObjectsLeft(t, r.Client)

			res, err := ptMoreReconcile(t, r)
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if res.RequeueAfter != 60*time.Second {
				t.Errorf("a credential that cannot be read must be retried, got %+v", res)
			}
			if left := bundleObjectsLeft(t, r.Client); left != want {
				t.Errorf("bundle objects = %d, want the %d already there kept so a transient read error causes no tracing gap", left, want)
			}
			if reason := policyAppliedReason(t, r.Client); !strings.HasPrefix(reason, "BundleSync: load credential Secret") {
				t.Errorf("PolicyApplied = %q, want the credential load failure", reason)
			}
			if got := reconciledCondition(t, r.Client); got != "False/BundleSync" {
				t.Errorf("Reconciled = %s, want False/BundleSync while the bundle cannot be updated", got)
			}
		})
	}
}

func TestPodTraceReconcile_UnreadableBundleKeepsRetrying(t *testing.T) {
	pt := narrowingTrace()
	objects := append([]client.Object{pt, exporterWithMissingCredential(), tenantNamespace("")}, existingBundle(pt, ptMoreSysNS)...)
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(objects...).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}

	res, err := ptMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 60*time.Second {
		t.Errorf("want the credential retry when the bundle cannot be read either, got %+v", res)
	}
}
