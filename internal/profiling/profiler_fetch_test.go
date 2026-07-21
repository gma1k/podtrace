package profiling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchGoroutine_FetchError(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", []int{1})
	p.foundPort.Store(1)
	r := p.FetchGoroutine(context.Background())
	if r.Available {
		t.Error("expected Available=false when the connection is refused")
	}
	if r.Error == "" {
		t.Error("expected a non-empty Error on connection failure")
	}
}

func TestFetchCPUProfile_ConnectionError(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", []int{1})
	p.foundPort.Store(1)
	r := p.FetchCPUProfile(context.Background(), 1*time.Second)
	if r.Available {
		t.Error("expected Available=false when the connection is refused")
	}
	if r.Error == "" {
		t.Error("expected a non-empty Error on connection failure")
	}
}

func TestFetchCPUProfile_SubSecondDurationClamped(t *testing.T) {
	var gotSeconds string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSeconds = r.URL.Query().Get("seconds")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("cpu-bytes"))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))

	r := p.FetchCPUProfile(context.Background(), 500*time.Millisecond)
	if !r.Available {
		t.Fatalf("expected Available=true, error=%q", r.Error)
	}
	if gotSeconds != "1" {
		t.Errorf("expected sub-second duration clamped to seconds=1, got seconds=%q", gotSeconds)
	}
}

func TestParseHeapText_SortAndTop20Cap(t *testing.T) {
	var sb []byte
	names := "ABCDEFGHIJKLMNOPQRSTUVWXY"
	for i := 0; i < len(names); i++ {

		line := "1: " + itoaLocal(int64((i+1)*1024)) + " [1: " + itoaLocal(int64((i+1)*1024)) + "] @\n"
		sb = append(sb, []byte(line)...)
		sb = append(sb, []byte("#\t0x0\tpkg.Func"+string(names[i])+"+0x0\tf.go:1\n\n")...)
	}
	samples := parseHeapText(string(sb))
	if len(samples) != 20 {
		t.Fatalf("expected top-20 cap, got %d samples", len(samples))
	}

	for i := 1; i < len(samples); i++ {
		if samples[i].Bytes > samples[i-1].Bytes {
			t.Fatalf("samples not sorted by bytes desc at %d", i)
		}
	}
	if samples[0].Bytes != int64(25*1024) {
		t.Errorf("expected largest sample first (%d), got %d", 25*1024, samples[0].Bytes)
	}
}

func TestParseGoroutineText_MalformedHeader(t *testing.T) {
	text := "goroutine 1 running no brackets here\n" +
		"goroutine 2 [chan receive]:\n"
	total, blocked := parseGoroutineText(text)
	if total != 2 {
		t.Errorf("expected total=2 (both header lines counted), got %d", total)
	}
	if blocked != 1 {
		t.Errorf("expected blocked=1 (only the well-formed blocked state), got %d", blocked)
	}
}

func itoaLocal(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
