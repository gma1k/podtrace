package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadObjectStoreCredentials_Unset(t *testing.T) {
	t.Setenv(envObjectStoreCredentialsDir, "")
	creds, err := loadObjectStoreCredentials()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds != nil {
		t.Fatalf("expected nil credentials when dir unset, got %v", creds)
	}
}

func TestLoadObjectStoreCredentials_MissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	t.Setenv(envObjectStoreCredentialsDir, missing)

	creds, err := loadObjectStoreCredentials()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds != nil {
		t.Fatalf("expected nil credentials for missing dir, got %v", creds)
	}
}

func TestLoadObjectStoreCredentials_PopulatedDir(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "access-key"), []byte("AKIA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret-key"), []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "..hidden"), []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv(envObjectStoreCredentialsDir, dir)

	creds, err := loadObjectStoreCredentials()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds == nil {
		t.Fatal("expected populated credentials map, got nil")
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 credential entries, got %d: %v", len(creds), keysOf(creds))
	}
	if string(creds["access-key"]) != "AKIA" {
		t.Errorf("access-key = %q, want %q", creds["access-key"], "AKIA")
	}
	if string(creds["secret-key"]) != "s3cr3t" {
		t.Errorf("secret-key = %q, want %q", creds["secret-key"], "s3cr3t")
	}
	if _, ok := creds["..hidden"]; ok {
		t.Error("expected '..'-prefixed entry to be skipped")
	}
	if _, ok := creds["nested"]; ok {
		t.Error("expected subdirectory to be skipped")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestUploadIfPresent_MissingReportFileIsNoOp(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "report.txt")
	err := uploadIfPresent(context.Background(), reportUploaderOptions{
		ReportFile:   missing,
		ReportToSpec: "configmap/ns/name",
	})
	if err != nil {
		t.Fatalf("expected nil for missing report file, got %v", err)
	}
}

func TestUploadIfPresent_PresentFileWritesSidecarHandoff(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(reportPath, []byte("hello report"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KUBECONFIG", "")

	err := uploadIfPresent(context.Background(), reportUploaderOptions{
		ReportFile:   reportPath,
		ReportToSpec: "configmap/ns/name",
	})
	if err == nil {
		t.Fatal("expected an error from in-cluster client build, got nil (did read short-circuit?)")
	}
	t.Logf("reached present-file branch, client build failed as expected: %v", err)
}

func TestPersistAndReadKeyHint_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := keyHintStateFile
	keyHintStateFile = filepath.Join(dir, "upload-key-hint.txt")
	t.Cleanup(func() { keyHintStateFile = orig })

	persistKeyHint("pod-2026-06-08T00-00-00Z.txt")

	got, ok := readPersistedKeyHint()
	if !ok {
		t.Fatal("expected persisted key hint to be readable")
	}
	if got != "pod-2026-06-08T00-00-00Z.txt" {
		t.Errorf("hint = %q, want %q", got, "pod-2026-06-08T00-00-00Z.txt")
	}

	raw, err := os.ReadFile(keyHintStateFile)
	if err != nil {
		t.Fatalf("state file not written: %v", err)
	}
	if string(raw) != "pod-2026-06-08T00-00-00Z.txt" {
		t.Errorf("on-disk hint = %q, want %q", raw, "pod-2026-06-08T00-00-00Z.txt")
	}
}

func TestReadPersistedKeyHint_MissingFile(t *testing.T) {
	dir := t.TempDir()
	orig := keyHintStateFile
	keyHintStateFile = filepath.Join(dir, "absent.txt")
	t.Cleanup(func() { keyHintStateFile = orig })

	if _, ok := readPersistedKeyHint(); ok {
		t.Error("expected ok=false when state file does not exist")
	}
}
