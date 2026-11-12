package tracing

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

type postLog struct {
	mu     sync.Mutex
	bodies []string
}

func (p *postLog) count(substr string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, b := range p.bodies {
		if substr == "" || strings.Contains(b, substr) {
			n++
		}
	}
	return n
}

func recordingServer(t *testing.T, failFor string) (*httptest.Server, *postLog) {
	t.Helper()
	log := &postLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		log.mu.Lock()
		log.bodies = append(log.bodies, string(body))
		log.mu.Unlock()
		if failFor != "" && strings.Contains(string(body), failFor) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

func managerWithOnly(t *testing.T, set func()) *Manager {
	t.Helper()
	saved := []string{config.OTLPEndpoint, config.JaegerEndpoint, config.SplunkEndpoint, config.DataDogEndpoint, config.ZipkinEndpoint}
	savedEnabled, savedRate := config.TracingEnabled, config.TracingSampleRate
	t.Cleanup(func() {
		config.OTLPEndpoint, config.JaegerEndpoint, config.SplunkEndpoint, config.DataDogEndpoint, config.ZipkinEndpoint = saved[0], saved[1], saved[2], saved[3], saved[4]
		config.TracingEnabled, config.TracingSampleRate = savedEnabled, savedRate
	})
	config.OTLPEndpoint, config.JaegerEndpoint, config.SplunkEndpoint, config.DataDogEndpoint, config.ZipkinEndpoint = "", "", "", "", ""
	config.TracingEnabled, config.TracingSampleRate = true, 1.0
	set()
	m, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func trackSpan(m *Manager, traceID, spanID string) {
	m.traceTracker.ProcessEvent(&events.Event{Type: events.EventDNS, TraceID: traceID, SpanID: spanID}, nil)
}

func TestADeliveredTraceIsNotResentWhenAnotherTraceInTheBatchFails(t *testing.T) {
	const delivered, refused = "aabbccddeeff00112233445566778899", "99887766554433221100ffeeddccbbaa"
	srv, log := recordingServer(t, refused)
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = srv.URL })
	trackSpan(m, delivered, "1122334455667788")
	trackSpan(m, refused, "8877665544332211")

	m.exportTraces(context.Background(), true)
	m.exportTraces(context.Background(), true)

	accepted := 0
	for _, body := range log.bodies {
		if strings.Contains(body, delivered) && !strings.Contains(body, refused) {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("collector accepted the delivered trace %d times, want 1", accepted)
	}
	if got := log.count(refused); got != 3 {
		t.Errorf("refused trace posted %d times, want 3 (shared batch, isolated alone, retried on the next export)", got)
	}
	if last := log.bodies[len(log.bodies)-1]; strings.Contains(last, delivered) {
		t.Error("the retry on the next export carried the delivered trace again")
	}
}

func TestSpansDeliveredBeforeAFailedBatchAreNotResent(t *testing.T) {
	const traceID = "aabbccddeeff00112233445566778899"
	srv, log := recordingServer(t, `"span-last"`)
	m := managerWithOnly(t, func() { config.SplunkEndpoint = srv.URL })
	blob := strings.Repeat("x", 8000)
	for i := range 100 {
		target := fmt.Sprintf("span-%02d", i)
		if i == 99 {
			target = "span-last"
		}
		m.traceTracker.ProcessEvent(&events.Event{
			Type:    events.EventDNS,
			TraceID: traceID,
			SpanID:  fmt.Sprintf("%016x", i+1),
			Target:  target,
			Details: blob,
		}, nil)
	}

	m.exportTraces(context.Background(), true)
	m.exportTraces(context.Background(), true)

	for _, span := range []string{`"span-00"`, `"span-30"`} {
		if got := log.count(span); got != 1 {
			t.Errorf("%s was delivered in the first batch but posted %d times, want 1", span, got)
		}
	}
	if got := log.count(`"span-last"`); got != 2 {
		t.Errorf("the span of the failed batch was posted %d times, want 2 (retried)", got)
	}
	if got := len(log.bodies); got != 3 {
		t.Errorf("collector received %d posts, want 3 (two batches, then only the failed one again)", got)
	}
}

func TestAnUnexportableSpanIsDroppedInsteadOfResentEveryTick(t *testing.T) {
	srv, log := recordingServer(t, "")
	m := managerWithOnly(t, func() { config.OTLPEndpoint = srv.URL })
	trackSpan(m, "aabbccddeeff00112233445566778899", "1122334455667788")
	trackSpan(m, "not-a-hex-trace-id", "1122334455667788")

	for range 3 {
		m.exportTraces(context.Background(), true)
	}

	if got := log.count(""); got != 1 {
		t.Errorf("collector received %d posts, want 1: the batch was re-sent because one span could never be exported", got)
	}
}
