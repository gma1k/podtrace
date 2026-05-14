package objectstore

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestAzureSink_SharedKeyUpload(t *testing.T) {
	var (
		mu        sync.Mutex
		gotMethod string
		gotPath   string
		gotCT     string
		gotBody   string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("x-ms-blob-content-type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	const fakeKey = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="

	sink, err := New(context.Background(), Config{
		URI: "azblob://devstoreaccount1/reports/diagnose/",
		Credentials: map[string][]byte{
			azureSecretKeyAccountKey: []byte(fakeKey),
			azureSecretKeyEndpoint:   []byte(srv.URL + "/devstoreaccount1"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	resolved, err := sink.Upload(context.Background(), "sess-1.txt", "text/plain", strings.NewReader("hello report"))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if want := "azblob://devstoreaccount1/reports/diagnose/sess-1.txt"; resolved != want {
		t.Errorf("resolvedURI = %q, want %q", resolved, want)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/devstoreaccount1/reports/diagnose/sess-1.txt") {
		t.Errorf("path = %q, want suffix /devstoreaccount1/reports/diagnose/sess-1.txt", gotPath)
	}
	if gotCT != "text/plain" {
		t.Errorf("content-type header = %q, want text/plain", gotCT)
	}
	if gotBody != "hello report" {
		t.Errorf("body = %q, want %q", gotBody, "hello report")
	}
}

func TestAzureSink_EmptyKeyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	const fakeKey = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="

	sink, err := New(context.Background(), Config{
		URI: "azblob://devstoreaccount1/reports/",
		Credentials: map[string][]byte{
			azureSecretKeyAccountKey: []byte(fakeKey),
			azureSecretKeyEndpoint:   []byte(srv.URL + "/devstoreaccount1"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if _, err := sink.Upload(context.Background(), "", "text/plain", strings.NewReader("x")); err == nil {
		t.Fatal("expected empty-key rejection, got nil")
	}
}