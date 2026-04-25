//go:build envtest
// +build envtest

// Envtest harness for the agent package.
//
// Brings up a real kube-apiserver + etcd once per `go test` invocation,
// installs the v1alpha1 CRDs, and hands each test a fresh namespace.
//
// Run with:
//
//   make envtest
//
// or directly:
//
//   KUBEBUILDER_ASSETS=$(setup-envtest use 1.30.x -p path) \
//     go test -tags=envtest -timeout 300s ./internal/agent/...

package agent

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
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
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

func setupSharedEnvtest(t *testing.T) (*runtime.Scheme, client.Client) {
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
			t.Skipf("envtest.Start failed (missing KUBEBUILDER_ASSETS?): %v", err)
			return
		}

		s := runtime.NewScheme()
		utilruntime.Must(clientgoscheme.AddToScheme(s))
		utilruntime.Must(podtracev1alpha1.AddToScheme(s))

		c, err := client.New(cfg, client.Options{Scheme: s})
		if err != nil {
			t.Fatalf("client.New: %v", err)
		}

		testEnv = env
		testScheme = s
		testClient = c
	})

	if testClient == nil {
		t.SkipNow()
	}
	return testScheme, testClient
}

func freshNamespace(t *testing.T, c client.Client) string {
	t.Helper()
	name := strings.ToLower(t.Name())
	// DNS-1123 label: lowercase alphanumerics and '-' only.
	name = strings.NewReplacer("/", "-", "_", "-", " ", "-").Replace(name)
	if len(name) > 60 {
		name = name[:60]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace %q: %v", name, err)
	}
	return name
}

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

// locateCRDPath materialises a Helm-directive-stripped copy of the
// chart's CRDs so envtest's YAML loader accepts them.
func locateCRDPath(t *testing.T) string {
	t.Helper()
	dir := findRepoRoot(t)
	src := filepath.Join(dir, "deploy", "charts", "podtrace", "crds")
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
		out := stripHelmDirectives(string(raw))
		if err := os.WriteFile(filepath.Join(dst, e.Name()), []byte(out), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return dst
}

func stripHelmDirectives(in string) string {
	var b strings.Builder
	for _, line := range strings.Split(in, "\n") {
		tl := strings.TrimSpace(line)
		if strings.HasPrefix(tl, "{{-") || strings.HasPrefix(tl, "{{") {
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

// createRunningPod is a test helper that creates a Pod and marks it Running.
// envtest has no kubelet, so .status.phase must be set via a status Update.
func createRunningPod(t *testing.T, c client.Client, ns, name, node string, labels map[string]string) *corev1.Pod {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "c", Image: "pause"}},
		},
	}
	if err := c.Create(ctx, p); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	p.Status.Phase = corev1.PodRunning
	if err := c.Status().Update(ctx, p); err != nil {
		t.Fatalf("update pod status: %v", err)
	}
	return p
}
