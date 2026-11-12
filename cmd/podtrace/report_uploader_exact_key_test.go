package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gma1k/podtrace/internal/reportsink/objectstore"
)

type recordedPut struct {
	path string
	body string
}

func uploadReportAndSummary(t *testing.T, reportTo string) []recordedPut {
	t.Helper()
	var mu sync.Mutex
	var puts []recordedPut
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		puts = append(puts, recordedPut{path: r.URL.Path, body: string(body)})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	writeCredentialsDir(t, map[string]string{
		"access_key_id":     "AKIATEST",
		"secret_access_key": "secret",
		"endpoint":          srv.URL,
		"force_path_style":  "true",
	})
	t.Setenv(objectstore.EnvAllowAmbientCredentials, "")
	t.Setenv("HOSTNAME", "pts-session-pod")
	orig := keyHintStateFile
	keyHintStateFile = filepath.Join(t.TempDir(), "hint")
	t.Cleanup(func() { keyHintStateFile = orig })

	summaryFile := filepath.Join(t.TempDir(), "summary.json")
	if err := os.WriteFile(summaryFile, []byte(`{"totalEvents":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := uploadToObjectStore(context.Background(), reportUploaderOptions{
		ReportToSpec: reportTo,
		SummaryFile:  summaryFile,
	}, []byte("report body"))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]recordedPut(nil), puts...)
}

func TestUploadToObjectStoreExactKeyKeepsReport(t *testing.T) {
	puts := uploadReportAndSummary(t, "s3://bucket/reports/fixed.txt")
	if len(puts) != 1 {
		t.Fatalf("exact key received %d uploads, want only the report: %+v", len(puts), puts)
	}
	if puts[0].path != "/bucket/reports/fixed.txt" || puts[0].body != "report body" {
		t.Fatalf("exact key holds %+v, want the report at /bucket/reports/fixed.txt", puts[0])
	}
}

func TestUploadToObjectStorePrefixWritesSummaryBesideReport(t *testing.T) {
	puts := uploadReportAndSummary(t, "s3://bucket/reports/")
	if len(puts) != 2 {
		t.Fatalf("prefix mode received %d uploads, want report and summary: %+v", len(puts), puts)
	}
	if puts[0].body != "report body" {
		t.Fatalf("first upload = %+v, want the report", puts[0])
	}
	if puts[1].path != puts[0].path+".summary.json" || puts[1].body != `{"totalEvents":1}` {
		t.Fatalf("summary upload = %+v, want %s.summary.json", puts[1], puts[0].path)
	}
}

func TestUploadToObjectStoreWarnsWhenTheSummaryCannotBeRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	writeCredentialsDir(t, map[string]string{
		"access_key_id":     "AKIATEST",
		"secret_access_key": "secret",
		"endpoint":          srv.URL,
		"force_path_style":  "true",
	})
	t.Setenv(objectstore.EnvAllowAmbientCredentials, "")
	orig := keyHintStateFile
	keyHintStateFile = filepath.Join(t.TempDir(), "hint")
	t.Cleanup(func() { keyHintStateFile = orig })

	stderr := captureStderr(t, func() {
		err := uploadToObjectStore(context.Background(), reportUploaderOptions{
			ReportToSpec: "s3://bucket/reports/",
			SummaryFile:  filepath.Join(t.TempDir(), "missing-summary.json"),
		}, []byte("report body"))
		if err != nil {
			t.Fatalf("upload: %v", err)
		}
	})
	if !strings.Contains(stderr, "summary not uploaded") {
		t.Fatalf("an unreadable summary was skipped silently; stderr: %q", stderr)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()
	defer func() { os.Stderr = saved }()
	fn()
	_ = w.Close()
	os.Stderr = saved
	return <-done
}
