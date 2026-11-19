package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/redactor"
)

func TestCommandActivityIsEmptyWithoutCommands(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{{Type: events.EventDNS}}}
	if got := formatCommandActivity(d, 10*time.Second, "Redis", events.EventRedisCmd); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestRedisActivityGroupsCommandsWithLatencyAndErrors(t *testing.T) {
	var evs []*events.Event
	for i := 0; i < 8; i++ {
		evs = append(evs, &events.Event{Type: events.EventRedisCmd, Details: "PING", LatencyNS: uint64(i+1) * 1_000_000})
	}
	evs = append(evs,
		&events.Event{Type: events.EventRedisCmd, Details: "AUTH", LatencyNS: 2_000_000, Error: -1},
		&events.Event{Type: events.EventRedisCmd, Details: "", LatencyNS: 500_000},
		&events.Event{Type: events.EventRedisCmd, Details: "GET\x1b[31m", LatencyNS: 500_000},
	)
	got := formatCommandActivity(&mockDiagnostician{events: evs}, 10*time.Second, "Redis", events.EventRedisCmd)
	for _, want := range []string{
		"Redis Activity:\n",
		"  Commands: 11 (1.1/sec)\n",
		"  Failed:   1 (9.1%)\n",
		"    - PING (8 calls), p50=",
		"max=8.00ms\n",
		"    - AUTH (1 calls), p50=2.00ms, p95=2.00ms, p99=2.00ms, max=2.00ms, errors=1\n",
		"    - unknown (1 calls)",
		"    - GET (1 calls)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("terminal escape leaked into the report:\n%q", got)
	}
	if strings.Index(got, "PING") > strings.Index(got, "AUTH") {
		t.Errorf("most frequent command must come first:\n%s", got)
	}
}

func TestCommandActivityHonoursTheTopLimit(t *testing.T) {
	var evs []*events.Event
	for i := 0; i < config.TopProcessesLimit+3; i++ {
		evs = append(evs, &events.Event{Type: events.EventMemcachedCmd, Details: fmt.Sprintf("op%02d", i)})
	}
	got := formatCommandActivity(&mockDiagnostician{events: evs}, time.Second, "Memcached", events.EventMemcachedCmd)
	if n := strings.Count(got, "    - "); n != config.TopProcessesLimit {
		t.Fatalf("%d command lines, want %d:\n%s", n, config.TopProcessesLimit, got)
	}
	if strings.Contains(got, "Failed:") {
		t.Errorf("no failures, yet a Failed line:\n%s", got)
	}
}

func TestKafkaActivityIsEmptyWithoutMessages(t *testing.T) {
	if got := formatKafkaActivity(&mockDiagnostician{}, time.Second); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestKafkaActivityReportsTopicsPerDirection(t *testing.T) {
	evs := []*events.Event{
		{Type: events.EventKafkaProduce, Details: "orders", Bytes: 2048, LatencyNS: 1_000_000},
		{Type: events.EventKafkaProduce, Details: "orders", Bytes: 2048, LatencyNS: 3_000_000},
		{Type: events.EventKafkaProduce, Details: "audit", LatencyNS: 1_000_000, Error: -1},
		{Type: events.EventKafkaFetch, Details: "payments", Bytes: 100, LatencyNS: 50_000_000},
		{Type: events.EventKafkaFetch, Details: "", LatencyNS: 10_000_000},
	}
	got := formatKafkaActivity(&mockDiagnostician{events: evs}, 10*time.Second)
	for _, want := range []string{
		"Kafka Activity:\n",
		"  Produced: 3 messages (0.3/sec), 1 failed\n",
		"  Top topics (produce):\n",
		"    - orders (2 messages, 4.00 KB), p50=",
		"    - audit (1 messages), p50=1.00ms, p95=1.00ms, p99=1.00ms, max=1.00ms, errors=1\n",
		"  Consumed: 2 messages (0.2/sec)\n",
		"  Top topics (consume):\n",
		"    - payments (1 messages, 100 B)",
		"    - unknown (1 messages)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestKafkaActivityWithOnlyConsumedMessages(t *testing.T) {
	got := formatKafkaActivity(&mockDiagnostician{events: []*events.Event{{Type: events.EventKafkaFetch, Details: "payments"}}}, time.Second)
	if strings.Contains(got, "Produced") || !strings.Contains(got, "  Consumed: 1 messages") {
		t.Fatalf("unexpected section:\n%s", got)
	}
}

func TestApplicationTracingIncludesCacheAndMessagingSections(t *testing.T) {
	d := &mockDiagnostician{
		startTime: time.Unix(0, 0),
		events: []*events.Event{
			{Type: events.EventRedisCmd, Details: "GET"},
			{Type: events.EventMemcachedCmd, Details: "get"},
			{Type: events.EventKafkaProduce, Details: "orders"},
		},
	}
	got := GenerateApplicationTracing(d, time.Second)
	for _, want := range []string{"Redis Activity:", "Memcached Activity:", "Kafka Activity:"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestOperationHelpersSkipNilEvents(t *testing.T) {
	evs := []*events.Event{nil, {Type: events.EventRedisCmd, Details: "GET", Error: -1}, nil}
	stats := groupOperations(evs, operationOrUnknown)
	if len(stats) != 1 || stats[0].count != 1 || stats[0].errors != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if n := countErrors(evs); n != 1 {
		t.Fatalf("countErrors = %d, want 1", n)
	}
}

func TestKafkaActivityHonoursTheTopLimit(t *testing.T) {
	var evs []*events.Event
	for i := 0; i < config.TopProcessesLimit+2; i++ {
		evs = append(evs, &events.Event{Type: events.EventKafkaProduce, Details: fmt.Sprintf("topic-%02d", i)})
	}
	got := formatKafkaActivity(&mockDiagnostician{events: evs}, time.Second)
	if n := strings.Count(got, "    - "); n != config.TopProcessesLimit {
		t.Fatalf("%d topic lines, want %d:\n%s", n, config.TopProcessesLimit, got)
	}
}

func TestCacheAndMessagingCountsSurviveReportRedaction(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventRedisCmd, Details: "AUTH"},
		{Type: events.EventRedisCmd, Details: "AUTH"},
		{Type: events.EventKafkaProduce, Details: "session", Bytes: 10},
		{Type: events.EventKafkaProduce, Details: "token"},
	}}
	text := formatCommandActivity(d, time.Second, "Redis", events.EventRedisCmd) + formatKafkaActivity(d, time.Second)
	redacted := redactor.Default().RedactText(text)
	if redacted != text {
		t.Fatalf("redaction changed the section:\nbefore:\n%s\nafter:\n%s", text, redacted)
	}
	for _, want := range []string{"AUTH (2 calls)", "session (1 messages, 10 B)", "token (1 messages)"} {
		if !strings.Contains(redacted, want) {
			t.Errorf("missing %q in:\n%s", want, redacted)
		}
	}
}
