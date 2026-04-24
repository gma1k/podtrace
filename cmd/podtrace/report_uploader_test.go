package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitForFile_Appears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(path, []byte("x"), 0o600)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := waitForFile(ctx, path, 10*time.Millisecond); err != nil {
		t.Fatalf("waitForFile: %v", err)
	}
}

func TestWaitForFile_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := waitForFile(ctx, "/no/such/path", 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected context error on missing file")
	}
}

func TestUploadIfPresent_MissingFileIsNoop(t *testing.T) {
	opts := reportUploaderOptions{
		ReportFile:   "/no/such/path",
		ReportToSpec: "configmap/ns/name",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Missing report file must not attempt an upload (no Kubernetes
	// client is available in unit tests); a nil return is the
	// contract.
	if err := uploadIfPresent(ctx, opts); err != nil {
		t.Fatalf("missing file should be no-op, got: %v", err)
	}
}

func TestRunReportUploader_TimeoutThenNoop(t *testing.T) {
	opts := reportUploaderOptions{
		ReportFile:     "/no/such/path",
		ReportToSpec:   "configmap/ns/name",
		WatchInterval:  20 * time.Millisecond,
		MaxWaitTimeout: 100 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// With the wait timeout expiring first, uploadIfPresent is called
	// with a missing file, which is a no-op. No error surfaces.
	if err := runReportUploader(ctx, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
