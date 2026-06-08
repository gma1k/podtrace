package objectstore

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type recordingLogger struct {
	mu     sync.Mutex
	events []retryLogEntry
}

type retryLogEntry struct {
	Backend string
	Method  string
	URL     string
	Status  int
	Attempt int
	Err     error
}

func (r *recordingLogger) OnAttempt(backend, method, url string, status, attempt int, _ time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, retryLogEntry{
		Backend: backend,
		Method:  method,
		URL:     url,
		Status:  status,
		Attempt: attempt,
		Err:     err,
	})
}

func TestCounterFor_ReturnsSameCounterForSameKey(t *testing.T) {
	p := newAzureRetryLogPolicy()
	first := p.counterFor("PUT example.com/blob")
	first.Add(3)
	second := p.counterFor("PUT example.com/blob")
	if first != second {
		t.Fatal("counterFor returned a different counter for the same key")
	}
	if got := second.Load(); got != 3 {
		t.Errorf("cached counter lost state: got %d want 3", got)
	}
	if other := p.counterFor("GET example.com/blob"); other == first {
		t.Error("distinct keys must not share a counter")
	}
}

func TestLoggingTransport_AttemptsIncrementPerSameURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	rl := &recordingLogger{}
	transport := newLoggingTransport(http.DefaultTransport, "test", rl)
	client := &http.Client{Transport: transport}

	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL + "/put-object")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		_ = resp.Body.Close()
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.events) != 3 {
		t.Fatalf("expected 3 logged attempts, got %d", len(rl.events))
	}
	for i, e := range rl.events {
		if e.Attempt != i+1 {
			t.Errorf("event[%d].Attempt = %d, want %d", i, e.Attempt, i+1)
		}
		if e.Status != http.StatusServiceUnavailable {
			t.Errorf("event[%d].Status = %d, want 503", i, e.Status)
		}
		if e.Backend != "test" {
			t.Errorf("event[%d].Backend = %q, want test", i, e.Backend)
		}
	}
}

func TestLoggingTransport_DifferentURLsResetCounter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rl := &recordingLogger{}
	client := &http.Client{Transport: newLoggingTransport(http.DefaultTransport, "test", rl)}

	if _, err := client.Get(srv.URL + "/object-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(srv.URL + "/object-b"); err != nil {
		t.Fatal(err)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(rl.events))
	}
	for _, e := range rl.events {
		if e.Attempt != 1 {
			t.Errorf("event for %s logged Attempt=%d, want 1 (distinct URLs must reset)", e.URL, e.Attempt)
		}
	}
}

func TestLoggingTransport_NilInnerUsesDefault(t *testing.T) {
	transport := newLoggingTransport(nil, "test", &recordingLogger{})
	if transport.inner != http.DefaultTransport {
		t.Error("nil inner must fall back to http.DefaultTransport")
	}
}
