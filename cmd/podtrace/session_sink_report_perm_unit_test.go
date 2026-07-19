package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUploadReport_ReportFileIsSidecarReadable(t *testing.T) {
	dir := t.TempDir()
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
