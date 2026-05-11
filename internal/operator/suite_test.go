//go:build envtest
// +build envtest

// Envtest harness for the operator package.
//
// One *testing.M-shared envtest.Environment is brought up for the whole
// suite so that every reconciler test reuses one kube-apiserver + etcd.
// Tests are isolated by unique namespace per subtest, never by env
// teardown — envtest.Start is the expensive bit (~5s).
//
// Run with:
//
//   make envtest-operator
//
// or directly:
//
//   KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) \
//     go test -tags=envtest -timeout 300s ./internal/operator/...

package operator

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

var (
	testEnvOnce sync.Once
	testEnv     *envtest.Environment
	testScheme  *runtime.Scheme
	testClient  client.Client
	testCfgLock sync.Mutex
)

// setupSharedEnvtest brings up the apiserver+etcd exactly once per
// `go test` invocation. Subsequent calls are no-ops. On failure the
// first call returns the error and subsequent calls observe it via
// testClient==nil → t.Skip.
func setupSharedEnvtest(t *testing.T) (*runtime.Scheme, client.Client, string) {
	t.Helper()
	testCfgLock.Lock()
	defer testCfgLock.Unlock()

	testEnvOnce.Do(func() {
		log.SetLogger(zap.New(zap.WriteTo(io.Discard)))

		crdPath := locateCRDPath(t)
		if _, err := os.Stat(crdPath); err != nil {
			t.Skipf("CRDs not found at %s: %v", crdPath, err)
			return
		}

		env := &envtest.Environment{
			CRDDirectoryPaths:     []string{crdPath},
			ErrorIfCRDPathMissing: true,
		}
		cfg, err := env.Start()
		if err != nil {
			t.Skipf("envtest.Start failed (likely missing KUBEBUILDER_ASSETS): %v", err)
			return
		}

		sch, err := NewScheme()
		if err != nil {
			t.Fatalf("NewScheme: %v", err)
		}

		c, err := client.New(cfg, client.Options{Scheme: sch})
		if err != nil {
			t.Fatalf("client.New: %v", err)
		}

		testEnv = env
		testScheme = sch
		testClient = c
	})

	if testClient == nil {
		t.SkipNow()
	}

	// Each test gets its own namespace so test resources do not collide
	// when run with -parallel. Namespaces are not cleaned up — envtest
	// tear-down at process exit handles it.
	ns := freshNamespace(t)
	return testScheme, testClient, ns
}

// freshNamespace creates a unique namespace and returns its name.
func freshNamespace(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(sanitiseDNS(t.Name())) + "-ns"
	// sanitiseDNS keeps names DNS-1123 safe; collapse to <=63 chars.
	if len(name) > 60 {
		name = name[:60]
	}
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := testClient.Create(ctx, nsObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace %q: %v", name, err)
	}
	return name
}

// ensureSystemNamespace creates podtrace-system once if it does not yet exist.
// Reconcilers write bundles here; tests share the same namespace.
//
// Safe to share across tests for bundle reconcilers because bundle names
// incorporate PodTrace UIDs, which are unique across tests. TracerConfig
// tests must use ensureDedicatedSystemNamespace instead, because the
// agent DaemonSet and RBAC names are fixed-singleton.
func ensureSystemNamespace(t *testing.T, c client.Client) string {
	t.Helper()
	const name = "podtrace-system"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create %s: %v", name, err)
	}
	return name
}

// ensureDedicatedSystemNamespace creates a test-owned system namespace
// of the form "podtrace-system-<suffix>". Use this for TracerConfig
// envtests, which contend for the singleton agent DaemonSet + RBAC
// names — each TracerConfig under test must live in its own system NS
// or reconciliation will fight over owner references.
func ensureDedicatedSystemNamespace(t *testing.T, c client.Client, suffix string) string {
	t.Helper()
	name := "podtrace-system-" + sanitiseDNS(suffix)
	if len(name) > 60 {
		name = name[:60]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create %s: %v", name, err)
	}
	return name
}

// ensureDefaultTracerConfig upserts the cluster-wide "default" TracerConfig.
// Session reconcile reads it to source the Job container image. Without
// it, Job pods fail apiserver admission for empty image. Idempotent:
// tests that need it can call unconditionally.
func ensureDefaultTracerConfig(t *testing.T, c client.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:test",
		},
	}
	err := c.Create(ctx, tc)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create default TracerConfig: %v", err)
	}
}

func ensureExporterConfig(t *testing.T, c client.Client, namespace, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint: "otel:4318",
				Protocol: podtracev1alpha1.OTLPProtocolHTTP,
			},
		},
	}
	err := c.Create(ctx, ec)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create ExporterConfig %s/%s: %v", namespace, name, err)
	}
}

// locateCRDPath reuses the stripHelmDirectives technique from the
// api/v1alpha1 envtest — the CRD YAMLs under deploy/charts/podtrace are
// wrapped with `{{- if .Values.crds.install }}` which plain YAML loaders
// reject. We materialize a cleaned copy in a tempdir at test time.
func locateCRDPath(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	src := filepath.Join(repoRoot, "deploy", "charts", "podtrace", "templates", "crds")
	dst := t.TempDir()

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("readdir %s: %v", src, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		cleaned := stripHelmDirectives(string(raw))
		if err := os.WriteFile(filepath.Join(dst, e.Name()), []byte(cleaned), 0o644); err != nil {
			t.Fatalf("write cleaned CRD: %v", err)
		}
	}
	return dst
}

func stripHelmDirectives(in string) string {
	var b strings.Builder
	for _, line := range strings.Split(in, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{{-") || strings.HasPrefix(trimmed, "{{") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
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

// reconcileUntil drives a single reconcile iteration repeatedly until
// `want` returns nil or the deadline passes. Tests use this instead of
// wiring a full manager — reconcilers take a ctrl.Request so direct
// invocation is simple and deterministic.
func reconcileUntil(t *testing.T, deadline time.Duration, want func() error, reconcile func() error) {
	t.Helper()
	end := time.Now().Add(deadline)
	for {
		if err := reconcile(); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if err := want(); err == nil {
			return
		}
		if time.Now().After(end) {
			if err := want(); err != nil {
				t.Fatalf("condition not met within %s: %v", deadline, err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
