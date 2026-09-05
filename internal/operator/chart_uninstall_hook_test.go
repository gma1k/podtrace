package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatalf("read %v: %v", parts, err)
	}
	return string(raw)
}

func TestUninstallRemovesTheTracerConfigByDefault(t *testing.T) {
	tpl := repoFile(t, "deploy", "charts", "podtrace", "templates", "cr-teardown.yaml")

	if !strings.Contains(tpl, "helm.sh/hook: pre-delete") {
		t.Error("the teardown hook is not a pre-delete hook, so it would run after the " +
			"release's own resources are already gone")
	}
	if !strings.Contains(tpl, "kubectl delete tracerconfig") {
		t.Error("the teardown Job does not delete the TracerConfig, which is what owns the " +
			"privileged agent DaemonSet")
	}
	if !strings.Contains(tpl, "not .Values.tracerConfig.retainOnUninstall") {
		t.Error("the teardown hook is not gated on tracerConfig.retainOnUninstall, so there is " +
			"no way to keep agents running across an uninstall")
	}
}

func TestRetainOnUninstallIsOptInAndSchemaChecked(t *testing.T) {
	values := repoFile(t, "deploy", "charts", "podtrace", "values.yaml")
	if !strings.Contains(values, "retainOnUninstall: false") {
		t.Error("retainOnUninstall must default to false: leaving a CAP_SYS_ADMIN DaemonSet " +
			"running on every node with no operator is not a safe default")
	}

	schema := repoFile(t, "deploy", "charts", "podtrace", "values.schema.json")
	if !strings.Contains(schema, "retainOnUninstall") {
		t.Error("retainOnUninstall is missing from values.schema.json, so a typo would be " +
			"accepted silently and the agents would be deleted anyway")
	}
}

func TestNoDocumentedReportCommandUsesTheDeadJSONPath(t *testing.T) {
	dead := `jsonpath='{.data.report\.txt}'`

	roots := []string{"docs", "deploy", "README.md"}
	var offenders []string
	for _, root := range roots {
		base := filepath.Join("..", "..", root)
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			if strings.Contains(string(raw), dead) {
				offenders = append(offenders, path)
			}
			return nil
		})
	}
	if len(offenders) > 0 {
		t.Errorf("these still tell the reader to run a command that returns nothing: %v. The "+
			"report key is report-<node>.txt; read every key instead, with "+
			"-o go-template='{{range $k,$v := .data}}{{$v}}{{end}}'", offenders)
	}
}
