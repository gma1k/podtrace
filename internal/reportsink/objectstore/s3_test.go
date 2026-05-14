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

func TestS3Sink_UploadRoundTrip(t *testing.T) {
	var (
		mu          sync.Mutex
		gotMethod   string
		gotPath     string
		gotCT       string
		gotBody     string
		gotContains map[string]string
	)
	gotContains = map[string]string{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		gotContains["authorization"] = r.Header.Get("Authorization")
		w.Header().Set("ETag", `"deadbeef"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	creds := map[string][]byte{
		s3SecretKeyAccessKeyID:     []byte("AKIATEST"),
		s3SecretKeySecretAccessKey: []byte("supersecret"),
		s3SecretKeyEndpoint:        []byte(srv.URL),
		s3SecretKeyForcePath:       []byte("true"),
		s3SecretKeyRegion:          []byte("us-east-1"),
	}
	sink, err := New(context.Background(), Config{
		URI:         "s3://my-bucket/reports/",
		Credentials: creds,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	body := strings.NewReader("hello report")
	resolved, err := sink.Upload(context.Background(), "sess-1.txt", "text/plain", body)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if want := "s3://my-bucket/reports/sess-1.txt"; resolved != want {
		t.Errorf("resolvedURI = %q, want %q", resolved, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/my-bucket/reports/sess-1.txt" {
		t.Errorf("path = %q, want /my-bucket/reports/sess-1.txt", gotPath)
	}
	if gotCT != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", gotCT)
	}
	if gotBody != "hello report" {
		t.Errorf("body = %q, want %q", gotBody, "hello report")
	}
	if gotContains["authorization"] == "" || !strings.Contains(gotContains["authorization"], "AKIATEST") {
		t.Errorf("missing or unexpected Authorization header: %q", gotContains["authorization"])
	}
}

func TestS3Sink_ExactKeyMode(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := New(context.Background(), Config{
		URI: "s3://bucket/exact/path/report.txt",
		Credentials: map[string][]byte{
			s3SecretKeyAccessKeyID:     []byte("k"),
			s3SecretKeySecretAccessKey: []byte("s"),
			s3SecretKeyEndpoint:        []byte(srv.URL),
			s3SecretKeyForcePath:       []byte("true"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if _, err := sink.Upload(context.Background(), "ignored.txt", "text/plain", strings.NewReader("x")); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if gotPath != "/bucket/exact/path/report.txt" {
		t.Errorf("path = %q, want /bucket/exact/path/report.txt (exact key mode should ignore hint)", gotPath)
	}
}

func TestS3Sink_EmptyKeyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := New(context.Background(), Config{
		URI: "s3://bucket/",
		Credentials: map[string][]byte{
			s3SecretKeyAccessKeyID:     []byte("k"),
			s3SecretKeySecretAccessKey: []byte("s"),
			s3SecretKeyEndpoint:        []byte(srv.URL),
			s3SecretKeyForcePath:       []byte("true"),
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