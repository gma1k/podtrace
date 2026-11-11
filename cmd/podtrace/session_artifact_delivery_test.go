package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/events"
)

func TestFinalizeDiagnoseOutputsReturnsDeliveryFailures(t *testing.T) {
	saveSinkGlobals(t)
	dir := t.TempDir()
	summaryFile = filepath.Join(dir, "missing", "summary.json")
	terminationMessagePath = filepath.Join(dir, "termination.json")
	reportTo = ""

	err := finalizeDiagnoseOutputs(context.Background(), "report", diagnose.NewDiagnostician())

	if err == nil || !strings.Contains(err.Error(), "summary-file") {
		t.Fatalf("finalizeDiagnoseOutputs = %v, want the summary-file failure", err)
	}
	if _, statErr := os.Stat(terminationMessagePath); statErr != nil {
		t.Errorf("one failed artifact stopped the others: %v", statErr)
	}
}

func TestFinalizeDiagnoseOutputsSucceeds(t *testing.T) {
	saveSinkGlobals(t)
	summaryFile = filepath.Join(t.TempDir(), "summary.json")
	terminationMessagePath = ""
	reportTo = ""

	if err := finalizeDiagnoseOutputs(context.Background(), "report", diagnose.NewDiagnostician()); err != nil {
		t.Fatalf("finalizeDiagnoseOutputs = %v, want nil", err)
	}
}

func runDiagnoseCapturingStdout(t *testing.T) (string, error) {
	t.Helper()
	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := runDiagnoseMode(context.Background(), make(chan *events.Event), "100ms", nil, nil, nil)
	_ = w.Close()
	os.Stdout = original
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

func TestRunDiagnoseModeFailsWhenAnArtifactIsLostButStillPrintsTheReport(t *testing.T) {
	saveSinkGlobals(t)
	origExport := exportFormat
	t.Cleanup(func() { exportFormat = origExport })
	exportFormat = ""
	summaryFile = filepath.Join(t.TempDir(), "missing", "summary.json")
	terminationMessagePath = ""
	reportTo = ""

	out, err := runDiagnoseCapturingStdout(t)

	if err == nil || !strings.Contains(err.Error(), "summary-file") {
		t.Errorf("runDiagnoseMode = %v, want the lost summary to fail the run", err)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("the report was not printed")
	}
}

func TestRunDiagnoseModeJoinsArtifactFailureWithExport(t *testing.T) {
	saveSinkGlobals(t)
	origExport := exportFormat
	t.Cleanup(func() { exportFormat = origExport })
	exportFormat = "json"
	summaryFile = filepath.Join(t.TempDir(), "missing", "summary.json")
	terminationMessagePath = ""
	reportTo = ""

	out, err := runDiagnoseCapturingStdout(t)

	if err == nil || !strings.Contains(err.Error(), "summary-file") {
		t.Errorf("runDiagnoseMode = %v, want the lost summary to fail the run", err)
	}
	if !strings.Contains(out, "{") {
		t.Errorf("the JSON export was not written: %q", out)
	}
}

func TestValidateReportTo(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		sessionJob  bool
		wantErrText string
	}{
		{name: "unset", spec: ""},
		{name: "configmap", spec: "configmap/ns/name"},
		{name: "secret any case", spec: "Secret/ns/name"},
		{name: "object store in a session Job", spec: "s3://bucket/key", sessionJob: true},
		{name: "object store elsewhere", spec: "s3://bucket/key", wantErrText: "report-uploader sidecar"},
		{name: "malformed", spec: "configmap/name", wantErrText: "kind/namespace/name"},
		{name: "unknown kind", spec: "widget/ns/name", wantErrText: "unsupported report-to kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := ""
			if tt.sessionJob {
				base = t.TempDir()
			}
			t.Setenv(config.EnvArtifactBaseDir, base)
			err := validateReportTo(tt.spec)
			if tt.wantErrText == "" && err != nil {
				t.Errorf("validateReportTo(%q) = %v, want nil", tt.spec, err)
			}
			if tt.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrText)) {
				t.Errorf("validateReportTo(%q) = %v, want %q", tt.spec, err, tt.wantErrText)
			}
		})
	}
}

func TestUploadReportRefusesObjectStoreOutsideASessionJob(t *testing.T) {
	t.Setenv(config.EnvArtifactBaseDir, "")
	orig := objectStoreReportFile
	objectStoreReportFile = filepath.Join(t.TempDir(), "report.txt")
	t.Cleanup(func() { objectStoreReportFile = orig })

	if err := uploadReport(context.Background(), "s3://bucket/key", "report"); err == nil {
		t.Fatal("an object-store report outside a session Job reported success")
	}
	if _, err := os.Stat(objectStoreReportFile); !os.IsNotExist(err) {
		t.Errorf("a hand-off file nobody uploads was written: %v", err)
	}
}

func TestRunPodtraceRejectsAnUndeliverableReportToBeforeTracing(t *testing.T) {
	saveSinkGlobals(t)
	useEmptyKubeconfig(t)
	t.Setenv(config.EnvArtifactBaseDir, "")
	reportTo = "s3://bucket/key"

	err := runPodtrace(&cobra.Command{}, []string{"x"})

	if err == nil || !strings.Contains(err.Error(), "report-uploader sidecar") {
		t.Fatalf("runPodtrace = %v, want the --report-to refusal", err)
	}
}

func TestUploadReportSecretUsesTheSecretSink(t *testing.T) {
	t.Setenv("KUBECONFIG", writeUnreachableKubeconfig(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := uploadReport(ctx, "secret/ns/name", "text")

	if err == nil || !strings.Contains(err.Error(), "upsert report Secret") {
		t.Fatalf("uploadReport = %v, want the Secret upsert attempted", err)
	}
}
