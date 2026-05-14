package v1alpha1_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// newClientWithExporter returns a fake client whose backing store already
// contains the given ExporterConfig in the given namespace. Used to
// exercise both the happy path (exporter exists) and the missing-exporter
// rejection without wiring a real apiserver.
func newClientWithExporter(t *testing.T, namespace, name string) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	builder := fake.NewClientBuilder().WithScheme(scheme)
	if name != "" {
		builder = builder.WithObjects(&podtracev1alpha1.ExporterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "x:4318"},
			},
		})
	}
	return builder.Build()
}

// validSelector is a reusable valid label selector for test fixtures.
func validSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
}

func TestPodTraceValidator_Create(t *testing.T) {
	cases := []struct {
		name      string
		spec      podtracev1alpha1.PodTraceSpec
		exporter  string // name of ExporterConfig pre-created in "default"
		wantError string // substring expected in the error; empty means no error
	}{
		{
			name: "happy-path-selector",
			spec: podtracev1alpha1.PodTraceSpec{
				Selector:    validSelector(),
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
			},
			exporter:  "prod-otlp",
			wantError: "",
		},
		{
			name: "happy-path-podrefs",
			spec: podtracev1alpha1.PodTraceSpec{
				PodRefs:     []podtracev1alpha1.PodRef{{Namespace: "default", Name: "pod-a"}},
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
			},
			exporter:  "prod-otlp",
			wantError: "",
		},
		{
			name: "neither-selector-nor-podrefs",
			spec: podtracev1alpha1.PodTraceSpec{
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
			},
			exporter:  "prod-otlp",
			wantError: "one of spec.selector or spec.podRefs must be set",
		},
		{
			name: "both-selector-and-podrefs",
			spec: podtracev1alpha1.PodTraceSpec{
				Selector:    validSelector(),
				PodRefs:     []podtracev1alpha1.PodRef{{Name: "pod-a"}},
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
			},
			exporter:  "prod-otlp",
			wantError: "mutually exclusive",
		},
		{
			name: "missing-exporter-ref",
			spec: podtracev1alpha1.PodTraceSpec{
				Selector:    validSelector(),
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "does-not-exist"},
			},
			exporter:  "prod-otlp", // pre-created but wrong name requested
			wantError: "ExporterConfig not found",
		},
		{
			name: "empty-exporter-ref",
			spec: podtracev1alpha1.PodTraceSpec{
				Selector:    validSelector(),
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: ""},
			},
			exporter:  "prod-otlp",
			wantError: "exporterRef.name is required",
		},
		{
			name: "empty-selector-counts-as-unset",
			spec: podtracev1alpha1.PodTraceSpec{
				Selector:    &metav1.LabelSelector{}, // pointer set but no labels
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
			},
			exporter:  "prod-otlp",
			wantError: "one of spec.selector or spec.podRefs must be set",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClientWithExporter(t, "default", tc.exporter)
			v := &podtracev1alpha1.PodTraceCustomValidator{Client: c}
			obj := &podtracev1alpha1.PodTrace{
				ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
				Spec:       tc.spec,
			}
			_, err := v.ValidateCreate(context.Background(), obj)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error to contain %q, got %q", tc.wantError, err.Error())
			}
		})
	}
}

func TestPodTraceSessionValidator_Create(t *testing.T) {
	baseSpec := func() podtracev1alpha1.PodTraceSessionSpec {
		return podtracev1alpha1.PodTraceSessionSpec{
			Selector:    validSelector(),
			Duration:    metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		}
	}

	cases := []struct {
		name      string
		mutate    func(*podtracev1alpha1.PodTraceSessionSpec)
		exporter  string
		wantError string
	}{
		{
			name:      "happy-path",
			mutate:    func(s *podtracev1alpha1.PodTraceSessionSpec) {},
			exporter:  "prod-otlp",
			wantError: "",
		},
		{
			name:      "zero-duration-rejected",
			mutate:    func(s *podtracev1alpha1.PodTraceSessionSpec) { s.Duration = metav1.Duration{} },
			exporter:  "prod-otlp",
			wantError: "duration must be greater than zero",
		},
		{
			name: "negative-duration-rejected",
			mutate: func(s *podtracev1alpha1.PodTraceSessionSpec) {
				s.Duration = metav1.Duration{Duration: -1 * time.Second}
			},
			exporter:  "prod-otlp",
			wantError: "duration must be greater than zero",
		},
		{
			name: "missing-selector-and-podrefs",
			mutate: func(s *podtracev1alpha1.PodTraceSessionSpec) {
				s.Selector = nil
				s.PodRefs = nil
			},
			exporter:  "prod-otlp",
			wantError: "one of spec.selector or spec.podRefs must be set",
		},
		{
			name: "dangling-exporter-ref",
			mutate: func(s *podtracev1alpha1.PodTraceSessionSpec) {
				s.ExporterRef.Name = "nope"
			},
			exporter:  "prod-otlp",
			wantError: "ExporterConfig not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClientWithExporter(t, "default", tc.exporter)
			v := &podtracev1alpha1.PodTraceSessionCustomValidator{Client: c}
			spec := baseSpec()
			tc.mutate(&spec)
			obj := &podtracev1alpha1.PodTraceSession{
				ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
				Spec:       spec,
			}
			_, err := v.ValidateCreate(context.Background(), obj)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error to contain %q, got %q", tc.wantError, err.Error())
			}
		})
	}
}

// TestPodTraceSessionValidator_ObjectStoreReportRef covers Phase 3:
// ObjectStore is no longer blanket-rejected; URI shape is validated
// instead.
func TestPodTraceSessionValidator_ObjectStoreReportRef(t *testing.T) {
	base := func() podtracev1alpha1.PodTraceSessionSpec {
		return podtracev1alpha1.PodTraceSessionSpec{
			Selector:    validSelector(),
			Duration:    metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		}
	}
	cases := []struct {
		name      string
		ref       *podtracev1alpha1.ObjectStoreReference
		wantError string
	}{
		{
			name: "s3-prefix-accepted",
			ref:  &podtracev1alpha1.ObjectStoreReference{URI: "s3://bucket/reports/"},
		},
		{
			name: "s3-key-accepted",
			ref:  &podtracev1alpha1.ObjectStoreReference{URI: "s3://bucket/path/report.txt"},
		},
		{
			name: "gs-accepted",
			ref:  &podtracev1alpha1.ObjectStoreReference{URI: "gs://bucket/prefix/"},
		},
		{
			name: "azblob-with-container-accepted",
			ref:  &podtracev1alpha1.ObjectStoreReference{URI: "azblob://acct/container/"},
		},
		{
			name:      "empty-uri-rejected",
			ref:       &podtracev1alpha1.ObjectStoreReference{URI: ""},
			wantError: "uri is required",
		},
		{
			name:      "unknown-scheme-rejected",
			ref:       &podtracev1alpha1.ObjectStoreReference{URI: "ftp://b/k"},
			wantError: "unsupported URI scheme",
		},
		{
			name:      "missing-host-rejected",
			ref:       &podtracev1alpha1.ObjectStoreReference{URI: "s3:///k"},
			wantError: "must include scheme and host",
		},
		{
			name:      "azblob-missing-container-rejected",
			ref:       &podtracev1alpha1.ObjectStoreReference{URI: "azblob://acct/"},
			wantError: "must include a container",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClientWithExporter(t, "default", "prod-otlp")
			v := &podtracev1alpha1.PodTraceSessionCustomValidator{Client: c}
			spec := base()
			spec.ReportRef = &podtracev1alpha1.ReportReference{ObjectStore: tc.ref}
			obj := &podtracev1alpha1.PodTraceSession{
				ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
				Spec:       spec,
			}
			_, err := v.ValidateCreate(context.Background(), obj)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("expected accept, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error containing %q, got %v", tc.wantError, err)
			}
		})
	}
}

// TestPodTraceSessionValidator_ReportRefExclusivity locks in that at
// most one sink can be set.
func TestPodTraceSessionValidator_ReportRefExclusivity(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &podtracev1alpha1.PodTraceSessionCustomValidator{Client: c}
	obj := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    validSelector(),
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
			ReportRef: &podtracev1alpha1.ReportReference{
				ConfigMap:   &corev1.LocalObjectReference{Name: "rpt"},
				ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://b/"},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil || !strings.Contains(err.Error(), "at most one of configMap, secret, objectStore") {
		t.Fatalf("expected mutual-exclusion rejection, got %v", err)
	}
}

func TestExporterConfigValidator_Create(t *testing.T) {
	cases := []struct {
		name      string
		spec      podtracev1alpha1.ExporterConfigSpec
		wantError string
	}{
		{
			name: "happy-path-otlp",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "host:4318"},
			},
		},
		{
			name: "happy-path-datadog",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeDataDog,
				DataDog: &podtracev1alpha1.DataDogExporter{
					APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "s", Key: "k"},
				},
			},
		},
		{
			name: "type-without-variant",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
			},
			wantError: "must be set when spec.type",
		},
		{
			name: "type-mismatch",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type:   podtracev1alpha1.ExporterTypeOTLP,
				Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "j:14268"},
			},
			wantError: "does not match populated field",
		},
		{
			name: "two-variants-set",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type:   podtracev1alpha1.ExporterTypeOTLP,
				OTLP:   &podtracev1alpha1.OTLPExporter{Endpoint: "a:4318"},
				Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "j:14268"},
			},
			wantError: "only one of spec.otlp",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &podtracev1alpha1.ExporterConfigCustomValidator{}
			obj := &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "default"},
				Spec:       tc.spec,
			}
			_, err := v.ValidateCreate(context.Background(), obj)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error to contain %q, got %q", tc.wantError, err.Error())
			}
		})
	}
}

// TestPodTraceValidator_NilClient ensures the webhook fails closed when
// the operator wires a validator without a client. This guards against a
// misconfiguration where referential checks would silently succeed.
func TestPodTraceValidator_NilClient(t *testing.T) {
	v := &podtracev1alpha1.PodTraceCustomValidator{Client: nil}
	_, err := v.ValidateCreate(context.Background(), &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    validSelector(),
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "webhook client not configured") {
		t.Fatalf("expected nil-client guard, got %v", err)
	}
}

// TestValidators_RejectWrongType covers the defensive type-assertion
// branches in every validator. A caller that mis-wires a manager could
// route a random runtime.Object into any ValidateCreate/Update; the
// validator must refuse rather than panic.
func TestValidators_RejectWrongType(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")

	cases := []struct {
		name string
		fn   func(context.Context, *corev1.ConfigMap) error
	}{
		{"PodTrace-Create", func(ctx context.Context, obj *corev1.ConfigMap) error {
			v := &podtracev1alpha1.PodTraceCustomValidator{Client: c}
			_, err := v.ValidateCreate(ctx, obj)
			return err
		}},
		{"PodTrace-Update", func(ctx context.Context, obj *corev1.ConfigMap) error {
			v := &podtracev1alpha1.PodTraceCustomValidator{Client: c}
			_, err := v.ValidateUpdate(ctx, obj, obj)
			return err
		}},
		{"PodTraceSession-Create", func(ctx context.Context, obj *corev1.ConfigMap) error {
			v := &podtracev1alpha1.PodTraceSessionCustomValidator{Client: c}
			_, err := v.ValidateCreate(ctx, obj)
			return err
		}},
		{"PodTraceSession-Update", func(ctx context.Context, obj *corev1.ConfigMap) error {
			v := &podtracev1alpha1.PodTraceSessionCustomValidator{Client: c}
			_, err := v.ValidateUpdate(ctx, obj, obj)
			return err
		}},
		{"ExporterConfig-Create", func(ctx context.Context, obj *corev1.ConfigMap) error {
			v := &podtracev1alpha1.ExporterConfigCustomValidator{}
			_, err := v.ValidateCreate(ctx, obj)
			return err
		}},
		{"ExporterConfig-Update", func(ctx context.Context, obj *corev1.ConfigMap) error {
			v := &podtracev1alpha1.ExporterConfigCustomValidator{}
			_, err := v.ValidateUpdate(ctx, obj, obj)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bogus := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "bogus"}}
			err := tc.fn(context.Background(), bogus)
			if err == nil {
				t.Fatal("expected error on wrong object type, got nil")
			}
			if !strings.Contains(err.Error(), "expected *") {
				t.Errorf("error does not mention expected type: %q", err.Error())
			}
		})
	}

}

// TestValidators_DeleteIsNoOp confirms all three validators accept
// deletion unconditionally. Blocking deletes is a common source of
// stuck resources; tests lock in the "never block delete" policy.
func TestValidators_DeleteIsNoOp(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")

	ptv := &podtracev1alpha1.PodTraceCustomValidator{Client: c}
	if _, err := ptv.ValidateDelete(context.Background(), &podtracev1alpha1.PodTrace{}); err != nil {
		t.Errorf("PodTrace ValidateDelete: %v", err)
	}

	ptsv := &podtracev1alpha1.PodTraceSessionCustomValidator{Client: c}
	if _, err := ptsv.ValidateDelete(context.Background(), &podtracev1alpha1.PodTraceSession{}); err != nil {
		t.Errorf("PodTraceSession ValidateDelete: %v", err)
	}

	ecv := &podtracev1alpha1.ExporterConfigCustomValidator{}
	if _, err := ecv.ValidateDelete(context.Background(), &podtracev1alpha1.ExporterConfig{}); err != nil {
		t.Errorf("ExporterConfig ValidateDelete: %v", err)
	}
}

// TestPodTraceValidator_Update exercises the ValidateUpdate path
// distinctly from Create, since an update to a previously-valid CR with
// a now-missing exporterRef must still be rejected.
func TestPodTraceValidator_Update(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &podtracev1alpha1.PodTraceCustomValidator{Client: c}

	oldPT := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    validSelector(),
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	newPT := oldPT.DeepCopy()
	newPT.Spec.ExporterRef.Name = "ghost"

	_, err := v.ValidateUpdate(context.Background(), oldPT, newPT)
	if err == nil || !strings.Contains(err.Error(), "ExporterConfig not found") {
		t.Fatalf("expected dangling-exporter rejection on update, got %v", err)
	}
}

// TestExporterConfigValidator_EmptyType catches the silent-failure mode
// where spec.type is the empty string but a typed field is set. The
// CRD enum marker rejects the empty string at the apiserver, but the
// webhook must also reject it defensively so unit tests exercising the
// helper cover the branch.
func TestExporterConfigValidator_EmptyType(t *testing.T) {
	v := &podtracev1alpha1.ExporterConfigCustomValidator{}
	obj := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "default"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: "", // not a valid enum
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "x:4318"},
		},
	}
	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil {
		t.Fatal("expected rejection of empty spec.type with populated variant")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPodTraceValidator_RejectsMalformedNamespaceSelector(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	badSel := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "team",
			Operator: "BogusOp",
		}},
	}

	cases := []struct {
		name string
		run  func() error
	}{
		{
			name: "PodTrace",
			run: func() error {
				v := &podtracev1alpha1.PodTraceCustomValidator{Client: c}
				_, err := v.ValidateCreate(context.Background(), &podtracev1alpha1.PodTrace{
					ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
					Spec: podtracev1alpha1.PodTraceSpec{
						Selector:          validSelector(),
						ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
						NamespaceSelector: badSel,
					},
				})
				return err
			},
		},
		{
			name: "PodTraceSession",
			run: func() error {
				v := &podtracev1alpha1.PodTraceSessionCustomValidator{Client: c}
				_, err := v.ValidateCreate(context.Background(), &podtracev1alpha1.PodTraceSession{
					ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "default"},
					Spec: podtracev1alpha1.PodTraceSessionSpec{
						Selector:          validSelector(),
						Duration:          metav1.Duration{Duration: time.Minute},
						ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
						NamespaceSelector: badSel,
					},
				})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil || !strings.Contains(err.Error(), "spec.namespaceSelector") {
				t.Fatalf("expected namespaceSelector rejection, got %v", err)
			}
		})
	}
}

func TestPodTraceValidator_AcceptsValidNamespaceSelectors(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &podtracev1alpha1.PodTraceCustomValidator{Client: c}

	cases := []struct {
		name string
		sel  *metav1.LabelSelector
	}{
		{name: "nil", sel: nil},
		{name: "empty-matches-all", sel: &metav1.LabelSelector{}},
		{name: "match-labels", sel: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}},
		{name: "match-expressions-in", sel: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "team",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"a", "b"},
			}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := &podtracev1alpha1.PodTrace{
				ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
				Spec: podtracev1alpha1.PodTraceSpec{
					Selector:          validSelector(),
					ExporterRef:       podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
					NamespaceSelector: tc.sel,
				},
			}
			if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
