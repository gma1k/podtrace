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
	return renderChartWithAPIVersions(t, nil, setFlags...)
}

func renderChartWithAPIVersions(t *testing.T, apiVersions []string, setFlags ...string) []byte {
	t.Helper()
	helm := helmAvailable(t)

	chartDir := chartDir(t)

	args := []string{"template", "podtrace", chartDir}
	for _, f := range setFlags {
		args = append(args, "--set", f)
	}
	for _, av := range apiVersions {
		args = append(args, "--api-versions", av)
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

func TestChart_DefaultValues(t *testing.T) {
	out := renderChart(t)
	resources := parseKinds(t, out)

	if resources["CustomResourceDefinition"] != 4 {
		t.Errorf("default `helm template` should render 4 CRDs; got %d", resources["CustomResourceDefinition"])
	}
	if resources["Namespace"] != 0 {
		t.Errorf("Namespace count: got %d want 0 (namespace is created by the bootstrap Job, not as a tracked resource)", resources["Namespace"])
	}
	if !bytes.Contains(out, []byte("namespace-bootstrap")) {
		t.Error("default render must include the namespace-bootstrap Job that creates the system namespace")
	}
	if resources["ValidatingWebhookConfiguration"] != 0 {
		t.Errorf("webhook should be disabled by default, got %d", resources["ValidatingWebhookConfiguration"])
	}
}

func TestChart_CRDsToggleOff(t *testing.T) {
	out := renderChart(t, "crds.install=false")
	resources := parseKinds(t, out)
	if resources["CustomResourceDefinition"] != 0 {
		t.Errorf("crds.install=false should suppress CRDs; got %d", resources["CustomResourceDefinition"])
	}
	if bytes.Contains(out, []byte("crd-labeler")) {
		t.Error("crds.install=false should also suppress the labeler Job")
	}
}

func TestChart_CRDsCarryKeepAnnotation(t *testing.T) {
	out := renderChart(t)
	// Each CRD carries the annotation. Expect at least 4 occurrences
	// (one per CRD); the labeler's hook-delete-policy line is unrelated.
	count := bytes.Count(out, []byte("helm.sh/resource-policy: keep"))
	if count < 4 {
		t.Errorf("keep annotation count: got %d want >= 4 (one per CRD)", count)
	}
}

// TestChart_CRDLabelerRendersAsPreInstallHook pins the migration
// contract: when crds.
func TestChart_CRDLabelerRendersAsPreInstallHook(t *testing.T) {
	out := renderChart(t)
	if !bytes.Contains(out, []byte("crd-labeler")) {
		t.Fatal("expected crd-labeler resources to render with default values")
	}
	if !bytes.Contains(out, []byte(`helm.sh/hook: pre-install,pre-upgrade`)) {
		t.Error("crd-labeler should be a pre-install,pre-upgrade hook")
	}
	if !bytes.Contains(out, []byte(`helm.sh/hook-weight: "-20"`)) {
		t.Error("crd-labeler should have hook-weight -20 (runs before CRDs at -10)")
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

// TestChart_OperatorToggleRendersFullStack asserts the operator stack
// renders by default and disappears when explicitly disabled.
func TestChart_OperatorToggleRendersFullStack(t *testing.T) {
	on := renderChart(t)
	off := renderChart(t, "operator.enabled=false")

	onKinds := parseKinds(t, on)
	offKinds := parseKinds(t, off)

	if offKinds["Deployment"] != 0 {
		t.Errorf("operator Deployment should not render with operator.enabled=false, got %d", offKinds["Deployment"])
	}
	for _, kind := range []string{"Deployment", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Service"} {
		if onKinds[kind] < 1 {
			t.Errorf("default render: expected >=1 %s, got %d", kind, onKinds[kind])
		}
	}
}

// TestChart_WebhookRequiresOperatorToRender asserts that webhook
// templates render only when BOTH operator AND webhook are enabled,
// because the webhook server runs inside the operator Deployment.
func TestChart_WebhookRequiresOperatorToRender(t *testing.T) {
	webhookOnly := renderChart(t, "operator.enabled=false", "webhook.enabled=true")
	both := renderChart(t, "operator.enabled=true", "webhook.enabled=true")

	woKinds := parseKinds(t, webhookOnly)
	bothKinds := parseKinds(t, both)

	// Webhook-alone still renders the ValidatingWebhookConfiguration
	// (the user may be managing the operator out-of-band) but the
	// webhook Service only makes sense when the operator renders too.
	if woKinds["Service"] > 0 {
		t.Errorf("webhook-only should not render operator Services, got %d", woKinds["Service"])
	}
	if bothKinds["ValidatingWebhookConfiguration"] < 1 {
		t.Error("operator+webhook: ValidatingWebhookConfiguration missing")
	}
	// Operator+webhook should render exactly two Services: metrics + webhook.
	if bothKinds["Service"] != 2 {
		t.Errorf("operator+webhook: expected 2 Services, got %d", bothKinds["Service"])
	}
}

// TestChart_CertManagerCertificateConditional asserts the cert-manager
// Certificate only renders when webhook is enabled AND certSource is
// "cert-manager" (not self-signed or external).
func TestChart_CertManagerCertificateConditional(t *testing.T) {
	with := renderChart(t, "operator.enabled=true", "webhook.enabled=true")
	withoutCM := renderChart(t, "operator.enabled=true", "webhook.enabled=true", "webhook.certSource=self-signed")

	if !bytes.Contains(with, []byte("kind: Certificate")) {
		t.Error("cert-manager default: Certificate should render")
	}
	if bytes.Contains(withoutCM, []byte("kind: Certificate")) {
		t.Error("webhook.certSource=self-signed: Certificate should NOT render")
	}
}

// TestChart_OperatorDeploymentSecurityContext locks in the unprivileged
// operator runtime: non-root, read-only rootfs, no privilege escalation,
// all caps dropped. A regression that loosens these would be a real
// security finding, so it belongs in CI.
func TestChart_OperatorDeploymentSecurityContext(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	for _, marker := range []string{
		"runAsNonRoot: true",
		"readOnlyRootFilesystem: true",
		"allowPrivilegeEscalation: false",
		`drop: ["ALL"]`,
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("operator Deployment missing hardened securityContext marker: %q", marker)
		}
	}
}

// TestChart_SystemNamespaceOverride verifies the operator reads its
// namespace from values.
func TestChart_SystemNamespaceOverride(t *testing.T) {
	out := renderChart(t, "namespace.name=custom-podtrace")
	if !bytes.Contains(out, []byte("namespace: custom-podtrace")) {
		t.Error("namespace.name override not reflected in rendered output")
	}
	if !bytes.Contains(out, []byte(`NS="custom-podtrace"`)) {
		t.Error("namespace.name override not threaded into the bootstrap Job's kubectl apply payload")
	}
}

// TestChart_TracerConfigRenderedWhenOperatorEnabled asserts the chart's
// default behavior: enabling the operator also creates a TracerConfig
// CR so the agent DaemonSet comes up without manual `kubectl apply`.
func TestChart_TracerConfigRenderedWhenOperatorEnabled(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	if !bytes.Contains(out, []byte("kind: TracerConfig")) {
		t.Fatal("operator.enabled=true should render a default TracerConfig")
	}
	// Image, systemNamespace, and session caps must reflect values.yaml
	// so the chart produces a self-consistent install.
	for _, marker := range []string{
		"name: default",
		`systemNamespace: "podtrace-system"`,
		"maxConcurrentSessionsPerNode: 2",
		`priorityClassName: "system-node-critical"`,
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("rendered TracerConfig missing %q", marker)
		}
	}
}

func TestChart_TracerConfigSuppressedWhenDisabled(t *testing.T) {
	out := renderChart(t, "operator.enabled=true", "tracerConfig.create=false")
	if bytes.Contains(out, []byte("tracerconfig.yaml: |")) {
		t.Error("tracerConfig.create=false should suppress the TracerConfig YAML in the cr-bootstrap ConfigMap")
	}
}

// TestChart_TracerConfigPropagatesValues asserts that values.yaml
// fields the user expects to flow into the rendered TracerConfig
// actually do — bumping eventBufferSize via --set must surface in
// the CR or the agent DaemonSet would fall back to defaults silently.
func TestChart_TracerConfigPropagatesValues(t *testing.T) {
	out := renderChart(t,
		"operator.enabled=true",
		"agent.eventBufferSize=20000",
		"agent.statusReportInterval=15s",
		"session.ttlSecondsAfterFinished=900",
		"tracerConfig.sidecarUploader=true",
	)
	for _, marker := range []string{
		"eventBufferSize: 20000",
		`statusReportInterval: "15s"`,
		"ttlSecondsAfterFinished: 900",
		"sidecarUploader: true",
	} {
		if !bytes.Contains(out, []byte(marker)) {
			t.Errorf("rendered TracerConfig missing %q", marker)
		}
	}
}

// TestChart_ServiceMonitorToggle verifies the ServiceMonitor renders
// only when explicitly enabled and only with the operator on, and
// that the rendered shape targets the operator's metrics Service.
func TestChart_ServiceMonitorToggle(t *testing.T) {
	off := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"}, "operator.enabled=true")
	on := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"},
		"operator.enabled=true",
		"metrics.serviceMonitor.enabled=true",
		"metrics.serviceMonitor.interval=1m",
	)

	if bytes.Contains(off, []byte("kind: ServiceMonitor")) {
		t.Error("ServiceMonitor should not render when toggle is off")
	}
	if !bytes.Contains(on, []byte("kind: ServiceMonitor")) {
		t.Fatal("metrics.serviceMonitor.enabled=true should render a ServiceMonitor")
	}
	for _, marker := range []string{
		"port: metrics",
		"interval: 1m",
		"path: /metrics",
		"app.kubernetes.io/component: operator",
	} {
		if !bytes.Contains(on, []byte(marker)) {
			t.Errorf("ServiceMonitor missing %q", marker)
		}
	}
}

// TestChart_PodMonitorToggle verifies the agent PodMonitor renders
// only when enabled and selects pods by the operator-applied
// component label.
func TestChart_PodMonitorToggle(t *testing.T) {
	off := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"})
	on := renderChartWithAPIVersions(t, []string{"monitoring.coreos.com/v1"}, "metrics.podMonitor.enabled=true")

	if bytes.Contains(off, []byte("kind: PodMonitor")) {
		t.Error("PodMonitor should not render when toggle is off")
	}
	if !bytes.Contains(on, []byte("kind: PodMonitor")) {
		t.Fatal("metrics.podMonitor.enabled=true should render a PodMonitor")
	}
	for _, marker := range []string{
		"podtrace.io/managed-by: podtrace-operator",
		"podtrace.io/component: agent",
		"port: metrics",
		"path: /metrics",
	} {
		if !bytes.Contains(on, []byte(marker)) {
			t.Errorf("PodMonitor missing %q", marker)
		}
	}
}

// TestChart_ExporterConfigExampleToggle asserts the optional starter
// ExporterConfig only renders when explicitly enabled. Default off
// keeps the chart from polluting random user namespaces with example
// resources.
func TestChart_ExporterConfigExampleToggle(t *testing.T) {
	off := renderChart(t, "operator.enabled=true")
	on := renderChart(t,
		"operator.enabled=true",
		"examples.exporterconfig.enabled=true",
		"examples.exporterconfig.namespace=demo",
		"examples.exporterconfig.endpoint=otel:4318",
	)
	if bytes.Contains(off, []byte("exporterconfig.yaml: |")) {
		t.Error("ExporterConfig example must not render in the cr-bootstrap ConfigMap when the toggle is off")
	}
	if !bytes.Contains(on, []byte("exporterconfig.yaml: |")) {
		t.Fatal("examples.exporterconfig.enabled=true should render an exporterconfig.yaml entry in the cr-bootstrap ConfigMap")
	}
	for _, marker := range []string{
		"namespace: demo",
		`endpoint: "otel:4318"`,
		"type: otlp",
	} {
		if !bytes.Contains(on, []byte(marker)) {
			t.Errorf("example ExporterConfig missing %q", marker)
		}
	}
}

func TestChart_MonitoringTemplatesAreNoopWithoutCRDs(t *testing.T) {
	out := renderChart(t,
		"operator.enabled=true",
		"metrics.serviceMonitor.enabled=true",
		"metrics.podMonitor.enabled=true",
	)
	if bytes.Contains(out, []byte("kind: ServiceMonitor")) {
		t.Error("ServiceMonitor should not render without monitoring.coreos.com/v1 CRD")
	}
	if bytes.Contains(out, []byte("kind: PodMonitor")) {
		t.Error("PodMonitor should not render without monitoring.coreos.com/v1 CRD")
	}
}

func TestChart_OperatorClusterRoleHasRoleAndRoleBindingVerbs(t *testing.T) {
	out := renderChart(t, "operator.enabled=true")
	if !bytes.Contains(out, []byte(`resources: ["roles", "rolebindings"]`)) {
		t.Error("operator ClusterRole missing roles/rolebindings rule")
	}
	if !bytes.Contains(out, []byte(`["get", "list", "watch", "create", "update", "patch", "delete"]`)) {
		t.Error("operator ClusterRole missing required verbs on roles/rolebindings")
	}
}

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
