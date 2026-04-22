package chart_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// These tests shell out to the `helm` binary. When it is not installed,
// the tests skip — the check is cheap and the signal is high when Helm
// is available (catches template regressions the Go code cannot see).

// chartSubPath is resolved against the repo root, which findChartDir
// discovers by walking up looking for go.mod. This lets the test run
// from any cwd (repo root or test/chart).
const chartSubPath = "deploy/charts/podtrace"

// helmAvailable reports whether the helm CLI is on PATH. The chart
// rendering tests require it; unit tests elsewhere do not.
func helmAvailable(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed; skipping chart rendering tests")
	}
	return path
}

// renderChart invokes `helm template` with the given value overrides and
// returns all rendered YAML documents as a single byte buffer. Failure
// to render fails the test.
func renderChart(t *testing.T, setFlags ...string) []byte {
	t.Helper()
	helm := helmAvailable(t)

	chartDir := chartDir(t)

	args := []string{"template", "podtrace", chartDir}
	for _, f := range setFlags {
		args = append(args, "--set", f)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(helm, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template %v: %v\nstderr: %s", args, err, stderr.String())
	}
	return stdout.Bytes()
}

// chartDir locates the Helm chart by walking up from cwd until it finds
// a go.mod (repo root marker), then joining chartSubPath.
func chartDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, chartSubPath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate repo root (go.mod) from %s", dir)
	return ""
}

// TestChart_DefaultValues renders the chart with stock values and asserts
// that exactly the expected resources appear. Any new template that ships
// "on by default" must be either explicitly added to this assertion or
// gated behind a Values toggle.
func TestChart_DefaultValues(t *testing.T) {
	out := renderChart(t)
	resources := parseKinds(t, out)

	// Expect: 4 CRDs + 1 Namespace.
	wantCRDs := 4
	gotCRDs := resources["CustomResourceDefinition"]
	if gotCRDs != wantCRDs {
		t.Errorf("CRDs rendered: got %d want %d", gotCRDs, wantCRDs)
	}
	if resources["Namespace"] != 1 {
		t.Errorf("Namespace count: got %d want 1", resources["Namespace"])
	}
	// Should NOT render the webhook by default (operator not enabled).
	if resources["ValidatingWebhookConfiguration"] != 0 {
		t.Errorf("webhook should be disabled by default, got %d", resources["ValidatingWebhookConfiguration"])
	}
}

// TestChart_CRDsCanBeDisabled asserts the crds.install toggle actually
// suppresses all four CRDs.
func TestChart_CRDsCanBeDisabled(t *testing.T) {
	out := renderChart(t, "crds.install=false")
	resources := parseKinds(t, out)
	if resources["CustomResourceDefinition"] != 0 {
		t.Errorf("crds.install=false still rendered %d CRDs", resources["CustomResourceDefinition"])
	}
	// Namespace should still render.
	if resources["Namespace"] != 1 {
		t.Errorf("Namespace missing with crds disabled")
	}
}

// TestChart_KeepAnnotationToggle asserts the keep annotation only
// appears when crds.keep is true. When false, helm uninstall will clean
// up the CRDs too.
func TestChart_KeepAnnotationToggle(t *testing.T) {
	withKeep := renderChart(t, "crds.keep=true")
	withoutKeep := renderChart(t, "crds.keep=false")

	if !bytes.Contains(withKeep, []byte("helm.sh/resource-policy: keep")) {
		t.Error("crds.keep=true did not produce the keep annotation")
	}
	if bytes.Contains(withoutKeep, []byte("helm.sh/resource-policy: keep")) {
		t.Error("crds.keep=false still produced the keep annotation")
	}
}

// TestChart_WebhookToggle asserts the ValidatingWebhookConfiguration is
// conditional on webhook.enabled.
func TestChart_WebhookToggle(t *testing.T) {
	enabled := renderChart(t, "webhook.enabled=true")
	if !bytes.Contains(enabled, []byte("kind: ValidatingWebhookConfiguration")) {
		t.Error("webhook.enabled=true did not produce the webhook resource")
	}

	// Paths must match the kubebuilder markers on the Go webhook types.
	// If a future refactor renames a webhook path, this test catches it.
	for _, path := range []string{
		"/validate-podtrace-io-v1alpha1-podtrace",
		"/validate-podtrace-io-v1alpha1-podtracesession",
		"/validate-podtrace-io-v1alpha1-exporterconfig",
	} {
		if !bytes.Contains(enabled, []byte(path)) {
			t.Errorf("webhook manifest missing path %q", path)
		}
	}
}

// TestChart_NamespacePSALabels locks in the privileged PSA enforcement
// on the system namespace. A silent regression that dropped these
// labels would let the agent DaemonSet be rejected at admission in
// clusters with restricted defaults.
func TestChart_NamespacePSALabels(t *testing.T) {
	out := renderChart(t)
	for _, label := range []string{
		"pod-security.kubernetes.io/enforce: privileged",
		"pod-security.kubernetes.io/audit: privileged",
		"pod-security.kubernetes.io/warn: privileged",
	} {
		if !bytes.Contains(out, []byte(label)) {
			t.Errorf("namespace missing PSA label %q", label)
		}
	}
}

// TestChart_SystemNamespaceOverride verifies the operator reads its
// namespace from values.
func TestChart_SystemNamespaceOverride(t *testing.T) {
	out := renderChart(t, "namespace.name=custom-podtrace")
	if !bytes.Contains(out, []byte("name: custom-podtrace")) {
		t.Error("namespace.name override not reflected in rendered output")
	}
}

// parseKinds decodes a multi-document YAML blob and returns a count of
// resources by Kind.
func parseKinds(t *testing.T, raw []byte) map[string]int {
	t.Helper()
	out := map[string]int{}

	for _, doc := range bytes.Split(raw, []byte("\n---")) {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		// helm prepends a "# Source:" comment — ignore empty/comment-only docs.
		if !containsAnyKind(doc) {
			continue
		}
		var hdr struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal(doc, &hdr); err != nil {
			t.Fatalf("yaml unmarshal: %v\n---\n%s", err, doc)
		}
		if hdr.Kind == "" {
			continue
		}
		out[hdr.Kind]++
	}
	return out
}

func containsAnyKind(doc []byte) bool {
	for _, line := range bytes.Split(doc, []byte("\n")) {
		if strings.HasPrefix(strings.TrimSpace(string(line)), "kind:") {
			return true
		}
	}
	return false
}
