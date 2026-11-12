package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestUploadReport_ReportFileIsSidecarReadable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvArtifactBaseDir, dir)
	orig := objectStoreReportFile
	objectStoreReportFile = filepath.Join(dir, "report.txt")
	t.Cleanup(func() { objectStoreReportFile = orig })

	if err := uploadReport(context.Background(), "s3://bucket/key", "report body"); err != nil {
		t.Fatalf("uploadReport: %v", err)
	}
	info, err := os.Stat(objectStoreReportFile)
	if err != nil {
		t.Fatalf("stat report file: %v", err)
	}
	if info.Mode().Perm()&0o004 == 0 {
		t.Errorf("report.txt mode = %v, must be other-readable for the nonroot sidecar", info.Mode().Perm())
	}
}

func TestWriteSummaryFileIsSidecarReadable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvArtifactBaseDir, dir)
	path := filepath.Join(dir, "summary.json")

	if err := writeSummaryFile(path, SessionSummary{TotalEvents: 1}); err != nil {
		t.Fatalf("writeSummaryFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat summary file: %v", err)
	}
	if info.Mode().Perm()&0o004 == 0 {
		t.Errorf("summary.json mode = %v, must be other-readable for the nonroot sidecar", info.Mode().Perm())
	}
}
