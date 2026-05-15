package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// newECTestScheme builds a scheme with core + podtrace v1alpha1
// registered.
func newECTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("clientgo scheme: %v", err)
	}
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("podtrace scheme: %v", err)
	}
	return s
}

// newECFakeClient wires the same field indexers the real manager
// registers.
func newECFakeClient(t *testing.T, scheme *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).
		WithIndex(&podtracev1alpha1.PodTrace{}, IndexFieldPodTraceExporterRef,
			func(o client.Object) []string {
				pt := o.(*podtracev1alpha1.PodTrace)
				if pt.Spec.ExporterRef.Name == "" {
					return nil
				}
				return []string{pt.Spec.ExporterRef.Name}
			},
		).
		WithIndex(&podtracev1alpha1.PodTraceSession{}, IndexFieldPodTraceSessionExporterRef,
			func(o client.Object) []string {
				pts := o.(*podtracev1alpha1.PodTraceSession)
				if pts.Spec.ExporterRef.Name == "" {
					return nil
				}
				return []string{pts.Spec.ExporterRef.Name}
			},
		).
		Build()
}

func reconcileEC(t *testing.T, c client.Client, scheme *runtime.Scheme, ns, name string) *podtracev1alpha1.ExporterConfig {
	t.Helper()
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got podtracev1alpha1.ExporterConfig
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &got); err != nil {
		t.Fatalf("get reconciled ec: %v", err)
	}
	return &got
}

func ecCondition(ec *podtracev1alpha1.ExporterConfig, typ string) *metav1.Condition {
	for i := range ec.Status.Conditions {
		if ec.Status.Conditions[i].Type == typ {
			return &ec.Status.Conditions[i]
		}
	}
	return nil
}

func TestExporterConfigReconciler_ReadyConditions(t *testing.T) {
	scheme := newECTestScheme(t)

	tests := []struct {
		name        string
		ec          *podtracev1alpha1.ExporterConfig
		secrets     []*corev1.Secret
		wantReady   bool
		wantReason  string
		wantMsgPart string
		wantStatus  metav1.ConditionStatus
	}{
		{
			name: "otlp with no secret refs → Ready=true",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "otlp", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type: podtracev1alpha1.ExporterTypeOTLP,
					OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "o:4317"},
				},
			},
			wantReady:  true,
			wantReason: ecReasonSecretsResolved,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name: "otlp with HeadersFromSecret missing → Ready=false SecretMissing",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "otlp", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type: podtracev1alpha1.ExporterTypeOTLP,
					OTLP: &podtracev1alpha1.OTLPExporter{
						Endpoint:          "o:4317",
						HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "missing"},
					},
				},
			},
			wantReady:   false,
			wantReason:  ecReasonSecretMissing,
			wantMsgPart: "Secret ns/missing not found",
			wantStatus:  metav1.ConditionFalse,
		},
		{
			name: "otlp with header ValueFrom key missing → Ready=false SecretKeyMissing",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "otlp", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type: podtracev1alpha1.ExporterTypeOTLP,
					OTLP: &podtracev1alpha1.OTLPExporter{
						Endpoint: "o:4317",
						Headers: []podtracev1alpha1.OTLPHeader{
							{Name: "X-Auth", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "auth", Key: "missing-key"}},
						},
					},
				},
			},
			secrets: []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "auth", Namespace: "ns"}, Data: map[string][]byte{"other-key": []byte("v")}},
			},
			wantReady:   false,
			wantReason:  ecReasonSecretKeyMissing,
			wantMsgPart: `no key "missing-key"`,
			wantStatus:  metav1.ConditionFalse,
		},
		{
			name: "splunk with token secret present → Ready=true",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "splunk", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type: podtracev1alpha1.ExporterTypeSplunk,
					Splunk: &podtracev1alpha1.SplunkExporter{
						Endpoint:       "https://splunk:8088",
						TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "hec", Key: "token"},
					},
				},
			},
			secrets: []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "hec", Namespace: "ns"}, Data: map[string][]byte{"token": []byte("xxx")}},
			},
			wantReady:  true,
			wantReason: ecReasonSecretsResolved,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name: "splunk with token secret missing → Ready=false",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "splunk", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type: podtracev1alpha1.ExporterTypeSplunk,
					Splunk: &podtracev1alpha1.SplunkExporter{
						Endpoint:       "https://splunk:8088",
						TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "hec", Key: "token"},
					},
				},
			},
			wantReady:  false,
			wantReason: ecReasonSecretMissing,
			wantStatus: metav1.ConditionFalse,
		},
		{
			name: "datadog with api key secret present → Ready=true",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type:    podtracev1alpha1.ExporterTypeDataDog,
					DataDog: &podtracev1alpha1.DataDogExporter{APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd", Key: "api-key"}},
				},
			},
			secrets: []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: "ns"}, Data: map[string][]byte{"api-key": []byte("k")}},
			},
			wantReady:  true,
			wantReason: ecReasonSecretsResolved,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name: "spec variant mismatch → Ready=false InvalidSpec",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type:   podtracev1alpha1.ExporterTypeOTLP,
					Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "http://j"},
				},
			},
			wantReady:  false,
			wantReason: ecReasonInvalidSpec,
			wantStatus: metav1.ConditionFalse,
		},
		{
			name: "jaeger with no secrets → Ready=true",
			ec: &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "j", Namespace: "ns"},
				Spec: podtracev1alpha1.ExporterConfigSpec{
					Type:   podtracev1alpha1.ExporterTypeJaeger,
					Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "http://j:14268"},
				},
			},
			wantReady:  true,
			wantReason: ecReasonSecretsResolved,
			wantStatus: metav1.ConditionTrue,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objs := []client.Object{tc.ec}
			for _, s := range tc.secrets {
				objs = append(objs, s)
			}
			c := newECFakeClient(t, scheme, objs...)
			got := reconcileEC(t, c, scheme, tc.ec.Namespace, tc.ec.Name)

			if got.Status.Ready != tc.wantReady {
				t.Errorf("Ready: got %v, want %v", got.Status.Ready, tc.wantReady)
			}
			cond := ecCondition(got, ConditionReady)
			if cond == nil {
				t.Fatalf("Ready condition missing")
			}
			if cond.Reason != tc.wantReason {
				t.Errorf("Reason: got %q, want %q", cond.Reason, tc.wantReason)
			}
			if cond.Status != tc.wantStatus {
				t.Errorf("ConditionStatus: got %q, want %q", cond.Status, tc.wantStatus)
			}
			if tc.wantMsgPart != "" && !strings.Contains(cond.Message, tc.wantMsgPart) {
				t.Errorf("Message: got %q, want substring %q", cond.Message, tc.wantMsgPart)
			}
			if got.Status.ObservedGeneration != got.Generation {
				t.Errorf("ObservedGeneration: got %d, want %d", got.Status.ObservedGeneration, got.Generation)
			}
		})
	}
}

func TestExporterConfigReconciler_ReferenceCounts(t *testing.T) {
	scheme := newECTestScheme(t)

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec1", Namespace: "ns"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "o:4317"},
		},
	}

	tests := []struct {
		name       string
		extra      []client.Object
		wantRefs   int32
		wantStatus metav1.ConditionStatus
	}{
		{
			name:       "zero references",
			wantRefs:   0,
			wantStatus: metav1.ConditionFalse,
		},
		{
			name: "one PodTrace reference",
			extra: []client.Object{
				&podtracev1alpha1.PodTrace{
					ObjectMeta: metav1.ObjectMeta{Name: "pt1", Namespace: "ns"},
					Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec1"}},
				},
			},
			wantRefs:   1,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name: "PodTrace plus running session",
			extra: []client.Object{
				&podtracev1alpha1.PodTrace{
					ObjectMeta: metav1.ObjectMeta{Name: "pt1", Namespace: "ns"},
					Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec1"}},
				},
				&podtracev1alpha1.PodTraceSession{
					ObjectMeta: metav1.ObjectMeta{Name: "pts1", Namespace: "ns"},
					Spec:       podtracev1alpha1.PodTraceSessionSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec1"}},
					Status:     podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateRunning},
				},
			},
			wantRefs:   2,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name: "completed session is excluded",
			extra: []client.Object{
				&podtracev1alpha1.PodTrace{
					ObjectMeta: metav1.ObjectMeta{Name: "pt1", Namespace: "ns"},
					Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec1"}},
				},
				&podtracev1alpha1.PodTraceSession{
					ObjectMeta: metav1.ObjectMeta{Name: "done", Namespace: "ns"},
					Spec:       podtracev1alpha1.PodTraceSessionSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec1"}},
					Status:     podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateCompleted},
				},
			},
			wantRefs:   1,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name: "failed session is excluded",
			extra: []client.Object{
				&podtracev1alpha1.PodTraceSession{
					ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "ns"},
					Spec:       podtracev1alpha1.PodTraceSessionSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec1"}},
					Status:     podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateFailed},
				},
			},
			wantRefs:   0,
			wantStatus: metav1.ConditionFalse,
		},
		{
			name: "PodTrace pointing at a different EC is not counted",
			extra: []client.Object{
				&podtracev1alpha1.PodTrace{
					ObjectMeta: metav1.ObjectMeta{Name: "pt-other", Namespace: "ns"},
					Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "other"}},
				},
			},
			wantRefs:   0,
			wantStatus: metav1.ConditionFalse,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objs := []client.Object{ec.DeepCopy()}
			objs = append(objs, tc.extra...)
			c := newECFakeClient(t, scheme, objs...)
			got := reconcileEC(t, c, scheme, ec.Namespace, ec.Name)

			if got.Status.ReferencedBy != tc.wantRefs {
				t.Errorf("ReferencedBy: got %d, want %d", got.Status.ReferencedBy, tc.wantRefs)
			}
			cond := ecCondition(got, ConditionReferenced)
			if cond == nil {
				t.Fatalf("Referenced condition missing")
			}
			if cond.Status != tc.wantStatus {
				t.Errorf("Referenced status: got %q, want %q", cond.Status, tc.wantStatus)
			}
		})
	}
}

func TestExporterConfigReconciler_NoOpSuppression(t *testing.T) {
	scheme := newECTestScheme(t)
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec1", Namespace: "ns", Generation: 1},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "o:4317"},
		},
	}
	c := newECFakeClient(t, scheme, ec.DeepCopy())

	got1 := reconcileEC(t, c, scheme, ec.Namespace, ec.Name)
	firstResourceVersion := got1.ResourceVersion

	got2 := reconcileEC(t, c, scheme, ec.Namespace, ec.Name)
	if got2.ResourceVersion != firstResourceVersion {
		t.Errorf("ResourceVersion bumped on no-op reconcile: %q → %q", firstResourceVersion, got2.ResourceVersion)
	}
}

func TestExporterConfigReconciler_NotFoundIsNoOp(t *testing.T) {
	scheme := newECTestScheme(t)
	c := newECFakeClient(t, scheme)
	r := &ExporterConfigReconciler{Client: c, Scheme: scheme}
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "ns", Name: "missing"},
	})
	if err != nil {
		t.Fatalf("expected nil error for missing EC, got %v", err)
	}
}

func TestClampMessage(t *testing.T) {
	short := "short message"
	if clampMessage(short) != short {
		t.Errorf("short message altered")
	}
	long := strings.Repeat("x", ecMaxConditionMessageLen+50)
	got := clampMessage(long)
	if len(got) != ecMaxConditionMessageLen {
		t.Errorf("clamped len = %d, want %d", len(got), ecMaxConditionMessageLen)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("clamped message should end with '...': %q", got[len(got)-5:])
	}
}
