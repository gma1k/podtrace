package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestBuildObjectKeyHint_PersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	origPath := keyHintStateFile
	keyHintStateFile = filepath.Join(dir, "key-hint.txt")
	t.Cleanup(func() { keyHintStateFile = origPath })

	t.Setenv("HOSTNAME", "session-pod-abc")

	first := buildObjectKeyHint()
	if first == "" {
		t.Fatal("first call returned empty hint")
	}
	if _, err := os.Stat(keyHintStateFile); err != nil {
		t.Fatalf("state file not persisted: %v", err)
	}

	second := buildObjectKeyHint()
	if second != first {
		t.Errorf("hint changed across restarts: %q -> %q", first, second)
	}

	if third := buildObjectKeyHint(); third != first {
		t.Errorf("hint changed on third call: %q -> %q", first, third)
	}
}

func TestBuildObjectKeyHint_FreshSuffixFormat(t *testing.T) {
	t.Setenv("HOSTNAME", "pod-xyz")
	fixed := time.Date(2026, 5, 13, 12, 34, 56, 0, time.UTC)
	got := freshObjectKeyHint(func() time.Time { return fixed })
	want := "pod-xyz-2026-05-13T12-34-56Z.txt"
	if got != want {
		t.Errorf("freshObjectKeyHint = %q, want %q", got, want)
	}
}

func TestBuildObjectKeyHint_EmptyHostname(t *testing.T) {
	t.Setenv("HOSTNAME", "")
	got := freshObjectKeyHint(func() time.Time { return time.Unix(0, 0).UTC() })
	if !strings.HasPrefix(got, "session-") {
		t.Errorf("missing HOSTNAME fallback, got %q", got)
	}
}

func TestReadPersistedKeyHint_TrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	origPath := keyHintStateFile
	keyHintStateFile = filepath.Join(dir, "key-hint.txt")
	t.Cleanup(func() { keyHintStateFile = origPath })

	if err := os.WriteFile(keyHintStateFile, []byte("  pod-1-2026-01-01T00-00-00Z.txt\n"), 0o644); err != nil {
		t.Fatalf("seed state file: %v", err)
	}
	got, ok := readPersistedKeyHint()
	if !ok || got != "pod-1-2026-01-01T00-00-00Z.txt" {
		t.Errorf("readPersistedKeyHint = %q, ok=%v", got, ok)
	}
}

func TestReadPersistedKeyHint_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	origPath := keyHintStateFile
	keyHintStateFile = filepath.Join(dir, "key-hint.txt")
	t.Cleanup(func() { keyHintStateFile = origPath })

	if err := os.WriteFile(keyHintStateFile, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty file: %v", err)
	}
	if _, ok := readPersistedKeyHint(); ok {
		t.Error("empty state file should be treated as absent, but readPersistedKeyHint returned ok=true")
	}
}

func TestUploadIfPresent_MissingFileIsNoop(t *testing.T) {
	opts := reportUploaderOptions{
		ReportFile:   "/no/such/path",
		ReportToSpec: "configmap/ns/name",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

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

	if err := runReportUploader(ctx, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
