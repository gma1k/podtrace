package profiling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

// These tests drive doProfile directly against a loopback httptest server to
// exercise the success-path merge branches (heap available, goroutine
// available, CPU metadata) that the indirect Run-based tests do not reach.

func TestDoProfile_HeapAvailable_MergesResult(t *testing.T) {
	const heapText = `heap profile: 1: 1024 [1: 1024] @ heap/1048576
1: 1024 [1: 1024] @
#	0x0	example.com/pkg.Alloc+0x0	file.go:1

`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(heapText))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	h := NewHandler(host, []int{port})
	h.profiler.foundPort.Store(int64(port))

	h.doProfile(context.Background(), ProfileHeap, 0)

	res := h.GetResult()
	if res == nil {
		t.Fatal("expected non-nil result after heap doProfile")
	}
	if res.HeapProfile == nil || !res.HeapProfile.Available {
		t.Error("expected available heap profile to be stored")
	}
	if !res.PprofAvailable {
		t.Error("expected PprofAvailable=true after available heap fetch")
	}
	if res.PodIP != host {
		t.Errorf("expected PodIP=%q, got %q", host, res.PodIP)
	}
}

func TestDoProfile_GoroutineAvailable_MergesResult(t *testing.T) {
	const goroutineText = `goroutine 1 [running]:
main.main()

goroutine 2 [chan receive]:
runtime.gopark()
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(goroutineText))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	h := NewHandler(host, []int{port})
	h.profiler.foundPort.Store(int64(port))

	h.doProfile(context.Background(), ProfileGoroutine, 0)

	res := h.GetResult()
	if res == nil {
		t.Fatal("expected non-nil result after goroutine doProfile")
	}
	if res.GoroutineProfile == nil || !res.GoroutineProfile.Available {
		t.Error("expected available goroutine profile to be stored")
	}
	if res.GoroutineProfile.GoroutineCount != 2 {
		t.Errorf("expected GoroutineCount=2, got %d", res.GoroutineProfile.GoroutineCount)
	}
	if !res.PprofAvailable {
		t.Error("expected PprofAvailable=true after available goroutine fetch")
	}
}

func TestDoProfile_HeapFetchError_NoEndpoint(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	h.doProfile(context.Background(), ProfileHeap, 0)

	res := h.GetResult()
	if res == nil {
		t.Fatal("expected non-nil result even on fetch error")
	}
	if res.HeapProfile == nil {
		t.Fatal("expected heap profile struct to be stored")
	}
	if res.HeapProfile.Available {
		t.Error("expected Available=false on fetch error")
	}
	if res.HeapProfile.Error == "" {
		t.Error("expected non-empty Error on fetch failure")
	}
	if res.PprofAvailable {
		t.Error("expected PprofAvailable=false when heap fetch failed")
	}
}

func TestDoProfile_GoroutineFetchError_NoEndpoint(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	h.doProfile(context.Background(), ProfileGoroutine, 0)

	res := h.GetResult()
	if res == nil {
		t.Fatal("expected non-nil result even on goroutine fetch error")
	}
	if res.GoroutineProfile == nil || res.GoroutineProfile.Available {
		t.Error("expected unavailable goroutine profile to be stored")
	}
}

func TestDoProfile_CPU_SetsMetadataOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake-cpu-profile-data"))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	h := NewHandler(host, []int{port})
	h.profiler.foundPort.Store(int64(port))

	h.doProfile(context.Background(), ProfileCPU, 0)

	res := h.GetResult()
	if res == nil {
		t.Fatal("expected non-nil result after CPU doProfile")
	}
	if !res.PprofAvailable {
		t.Error("expected PprofAvailable=true after successful CPU fetch")
	}
	if res.HeapProfile != nil || res.GoroutineProfile != nil {
		t.Error("CPU profile should not populate heap/goroutine profiles")
	}
}

func TestDoProfile_CPU_FetchError_NoEndpoint(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	h.doProfile(context.Background(), ProfileCPU, 2*time.Second)

	res := h.GetResult()
	if res == nil {
		t.Fatal("expected non-nil result even on CPU fetch error")
	}
	if res.PprofAvailable {
		t.Error("expected PprofAvailable=false when CPU fetch failed")
	}
}

func TestDoProfile_DefaultDurationApplied(t *testing.T) {
	if config.ProfilingDefaultDuration <= 0 {
		t.Fatalf("expected positive default profiling duration, got %v", config.ProfilingDefaultDuration)
	}
}
