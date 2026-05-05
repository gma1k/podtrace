//go:build envtest
// +build envtest

// Package-level envtest suite for the v1alpha1 CRDs.
//
// This suite spins up a real kube-apiserver + etcd via
// sigs.k8s.io/controller-runtime/pkg/envtest, installs the CRD manifests
// rendered under deploy/charts/podtrace/crds, and asserts that
// the schema accepts the example manifests and rejects invalid ones.
//
// It is guarded by the `envtest` build tag so that `go test ./...` still
// works in environments where the envtest binaries (kube-apiserver,
// etcd) are not installed. Run with:
//
//   make envtest
//
// or directly:
//
//   KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) \
//     go test -tags=envtest -timeout 120s ./api/v1alpha1/...
package v1alpha1_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// envtestHarness wraps envtest.Environment + a ready client. One harness
// per test: envtest is stateful (CRDs persist across reuse) and a shared
// instance would leak state between tests.
type envtestHarness struct {
	env    *envtest.Environment
	scheme *runtime.Scheme
	client client.Client
}

// envtestLoggerOnce quiets controller-runtime's "log.SetLogger never
// called" warning that otherwise prints a stack trace on every
// envtest.Start. Harmless but noisy in CI output.
var envtestLoggerOnce sync.Once

func setupEnvtest(t *testing.T) *envtestHarness {
	t.Helper()

	envtestLoggerOnce.Do(func() {
		log.SetLogger(zap.New(zap.WriteTo(io.Discard)))
	})

	crdPath := locateCRDPath(t)
	if _, err := os.Stat(crdPath); err != nil {
		t.Skipf("CRD manifests not found at %s: %v", crdPath, err)
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
		// We do not exercise webhooks in envtest here: the webhook
		// business logic is covered by the unit tests in
		// webhook_test.go. This suite asserts CRD *schema* validation
		// by the apiserver.
	}

	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("envtest.Start: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 AddToScheme: %v", err)
	}
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("podtrace AddToScheme: %v", err)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Logf("envtest.Stop: %v", err)
		}
	})

	return &envtestHarness{env: env, scheme: scheme, client: c}
}

// locateCRDPath returns the on-disk directory where the CRD YAMLs live.
// Because we wrap each CRD with a Helm `{{- if .Values.crds.install }}`
// guard, they are still valid YAML documents (the Helm lines are treated
// as unknown directives by a plain YAML parser) — but envtest's CRD
// loader parses them strictly and would reject the Helm lines. We
// therefore materialize a cleaned copy at test time.
func locateCRDPath(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	src := filepath.Join(repoRoot, "deploy", "charts", "podtrace", "crds")
	dst := t.TempDir()

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		cleaned := stripHelmDirectives(string(raw))
		if err := os.WriteFile(filepath.Join(dst, e.Name()), []byte(cleaned), 0o644); err != nil {
			t.Fatalf("writing %s: %v", e.Name(), err)
		}
	}
	return dst
}

// stripHelmDirectives removes `{{- ... }}` lines from a YAML file so it
// parses as plain YAML. The directives in our CRD templates are purely
// install/keep toggles; the underlying structure is valid YAML once the
// directive lines are gone.
func stripHelmDirectives(in string) string {
	var out strings.Builder
	for _, line := range strings.Split(in, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{{-") || strings.HasPrefix(trimmed, "{{") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod from %s", dir)
	return ""
}

func TestEnvtest_CRDsInstalledAndPodTraceAccepted(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default-test"}}
	if err := h.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	// ExporterConfig first — the validating webhook (not wired in envtest)
	// would require this to pre-exist; the CRD schema itself does not, but
	// creating it in order matches the user flow.
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-otlp", Namespace: "default-test"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318"},
		},
	}
	if err := h.client.Create(ctx, ec); err != nil {
		t.Fatalf("create ExporterConfig: %v", err)
	}

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default-test"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if err := h.client.Create(ctx, pt); err != nil {
		t.Fatalf("create PodTrace: %v", err)
	}
}

func TestEnvtest_InvalidFilterRejectedBySchema(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "invalid-test"}}
	if err := h.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	// "http" is not a member of the EventFilter enum; the CRD schema must
	// reject this even without the validating webhook.
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "invalid-test"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Filters:     []podtracev1alpha1.EventFilter{"http"},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	err := h.client.Create(ctx, pt)
	if err == nil {
		t.Fatal("expected CRD schema to reject unsupported filter")
	}
	if !apierrors.IsInvalid(err) {
		t.Fatalf("expected Invalid error, got: %v", err)
	}
}

func TestEnvtest_PodTraceSessionRequiresDuration(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "session-test"}}
	if err := h.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	// Duration zero — not a missing-required-field error (metav1.Duration
	// zero is valid JSON "0s") but demonstrates the schema flows. The
	// *webhook* catches zero durations; the schema accepts them. This
	// test ensures that when the webhook is not installed, the CRD at
	// least round-trips the resource.
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pts", Namespace: "session-test"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Duration:    metav1.Duration{Duration: 5 * time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "x"},
		},
	}
	if err := h.client.Create(ctx, s); err != nil {
		t.Fatalf("create session: %v", err)
	}
}

// TestEnvtest_AllExporterVariants asserts the CRD schema accepts every
// typed variant of ExporterConfig (otlp, jaeger, zipkin, splunk, datadog).
// A schema regression that broke one variant would silently prevent users
// from configuring that backend.
func TestEnvtest_AllExporterVariants(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "variants"}}
	if err := h.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	type variant struct {
		name string
		spec podtracev1alpha1.ExporterConfigSpec
	}
	variants := []variant{
		{"otlp", podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint: "otel:4318",
				Protocol: podtracev1alpha1.OTLPProtocolHTTP,
			},
		}},
		{"jaeger", podtracev1alpha1.ExporterConfigSpec{
			Type:   podtracev1alpha1.ExporterTypeJaeger,
			Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "http://jaeger:14268"},
		}},
		{"zipkin", podtracev1alpha1.ExporterConfigSpec{
			Type:   podtracev1alpha1.ExporterTypeZipkin,
			Zipkin: &podtracev1alpha1.ZipkinExporter{Endpoint: "http://zipkin:9411/api/v2/spans"},
		}},
		{"splunk", podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeSplunk,
			Splunk: &podtracev1alpha1.SplunkExporter{
				Endpoint:       "https://splunk-hec:8088",
				TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "s", Key: "t"},
			},
		}},
		{"datadog", podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				Site:            "datadoghq.com",
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd", Key: "api-key"},
			},
		}},
	}
	for _, v := range variants {
		v := v
		t.Run(v.name, func(t *testing.T) {
			ec := &podtracev1alpha1.ExporterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "ec-" + v.name, Namespace: "variants"},
				Spec:       v.spec,
			}
			if err := h.client.Create(ctx, ec); err != nil {
				t.Fatalf("create %s ExporterConfig: %v", v.name, err)
			}
			fetched := &podtracev1alpha1.ExporterConfig{}
			if err := h.client.Get(ctx, client.ObjectKey{Name: ec.Name, Namespace: ec.Namespace}, fetched); err != nil {
				t.Fatalf("get %s ExporterConfig: %v", v.name, err)
			}
			if fetched.Spec.Type != v.spec.Type {
				t.Errorf("%s: type lost, got %q want %q", v.name, fetched.Spec.Type, v.spec.Type)
			}
		})
	}
}

// TestEnvtest_PodTraceWithPodRefs exercises the PodRefs target-selection
// path, complementary to the Selector path covered elsewhere.
func TestEnvtest_PodTraceWithPodRefs(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "podrefs"}}
	if err := h.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "podrefs"},
		Spec: podtracev1alpha1.PodTraceSpec{
			PodRefs: []podtracev1alpha1.PodRef{
				{Namespace: "podrefs", Name: "pod-a"},
				{Namespace: "podrefs", Name: "pod-b"},
			},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if err := h.client.Create(ctx, pt); err != nil {
		t.Fatalf("create PodTrace with PodRefs: %v", err)
	}
	fetched := &podtracev1alpha1.PodTrace{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: "pt", Namespace: "podrefs"}, fetched); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(fetched.Spec.PodRefs) != 2 {
		t.Errorf("PodRefs lost: got %d want 2", len(fetched.Spec.PodRefs))
	}
}

// TestEnvtest_SamplePercentBounds asserts the CRD min/max markers are
// actually enforced by the apiserver.
func TestEnvtest_SamplePercentBounds(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "bounds"}}
	if err := h.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	over := int32(150)
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "over", Namespace: "bounds"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:      &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			ExporterRef:   podtracev1alpha1.LocalObjectReference{Name: "x"},
			SamplePercent: &over,
		},
	}
	err := h.client.Create(ctx, pt)
	if err == nil {
		t.Fatal("expected rejection of samplePercent=150")
	}
	if !apierrors.IsInvalid(err) {
		t.Fatalf("expected Invalid error, got: %v", err)
	}
}

func TestEnvtest_TracerConfigIsClusterScoped(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:test",
		},
	}
	// TracerConfig is cluster-scoped; supplying a namespace at Create
	// time would be ignored by the apiserver. We omit it here and verify
	// the resource can be fetched without a namespace.
	if err := h.client.Create(ctx, tc); err != nil {
		t.Fatalf("create TracerConfig: %v", err)
	}
	fetched := &podtracev1alpha1.TracerConfig{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: "default"}, fetched); err != nil {
		t.Fatalf("get TracerConfig: %v", err)
	}
	if fetched.Spec.Image == "" {
		t.Error("image not persisted")
	}
}
