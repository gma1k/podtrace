package profiling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchText_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("heap profile body"))
	}))
	defer srv.Close()

	p := NewPodProfiler("127.0.0.1", nil)
	body, raw, err := p.fetchText(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchText: unexpected error %v", err)
	}
	if body != "heap profile body" {
		t.Errorf("body=%q want %q", body, "heap profile body")
	}
	if string(raw) != body {
		t.Errorf("raw=%q want %q", string(raw), body)
	}
}

func TestFetchText_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewPodProfiler("127.0.0.1", nil)
	_, _, err := p.fetchText(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error on HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q should mention status 500", err.Error())
	}
}

func TestFetchText_BadURL(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", nil)
	if _, _, err := p.fetchText(context.Background(), "://not-a-url"); err == nil {
		t.Error("expected error building request for malformed URL")
	}
}

func TestFetchText_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	p := NewPodProfiler("127.0.0.1", nil)
	if _, _, err := p.fetchText(context.Background(), url); err == nil {
		t.Error("expected transport error against closed server")
	}
}
