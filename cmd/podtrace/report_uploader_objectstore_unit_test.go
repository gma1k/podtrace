package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadToObjectStore_CredentialsDirIsFile(t *testing.T) {

	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envObjectStoreCredentialsDir, f)

	err := uploadToObjectStore(context.Background(), reportUploaderOptions{
		ReportToSpec: "s3://bucket/key",
	}, []byte("report body"))
	if err == nil || !strings.Contains(err.Error(), "object-store credentials") {
		t.Fatalf("expected object-store credentials error, got %v", err)
	}
}

func TestUploadToObjectStore_UnsupportedScheme(t *testing.T) {

	t.Setenv(envObjectStoreCredentialsDir, "")

	err := uploadToObjectStore(context.Background(), reportUploaderOptions{
		ReportToSpec: "foo://bucket/key",
	}, []byte("report body"))
	if err == nil {
		t.Fatal("expected error for unsupported scheme, got nil")
	}
	if !strings.Contains(err.Error(), "object-store sink") {
		t.Fatalf("expected wrapped object-store sink error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported URI scheme") {
		t.Fatalf("expected underlying unsupported-scheme error, got %v", err)
	}
}
