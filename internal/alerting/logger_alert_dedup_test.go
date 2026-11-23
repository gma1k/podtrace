package alerting

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/gma1k/podtrace/internal/config"
)

func loggerAlert(t *testing.T, msg string) *Alert {
	t.Helper()
	alert := CreateAlertFromLog(zapcore.WarnLevel, msg, nil, "", "")
	if alert == nil {
		t.Fatal("CreateAlertFromLog returned nil with an enabled manager")
	}
	return alert
}

func TestLoggerAlertsAreTaggedWithTheLoggerSource(t *testing.T) {
	defer SetGlobalManager(nil)
	SetGlobalManager(&Manager{enabled: true})

	if got := loggerAlert(t, "m").Source; got != AlertSourceLogger {
		t.Errorf("Source = %q, want %q", got, AlertSourceLogger)
	}
}

func TestLoggerAlertKeysTellDistinctMessagesApart(t *testing.T) {
	defer SetGlobalManager(nil)
	SetGlobalManager(&Manager{enabled: true})

	panicked := loggerAlert(t, "recovered from panic parsing untrusted binary")
	other := loggerAlert(t, "kernel aggregation map is evicting rows")
	again := loggerAlert(t, "recovered from panic parsing untrusted binary")

	if panicked.Key() == other.Key() {
		t.Error("two different log warnings share a dedup key, so the first masks the second")
	}
	if panicked.Key() != again.Key() {
		t.Error("the same log warning got two dedup keys, so repeats are never deduplicated")
	}
}

func TestNonLoggerAlertKeysStillIgnoreTheMessage(t *testing.T) {
	base := Alert{Severity: SeverityWarning, Source: AlertSourceIssue, Title: "p99 latency high", Namespace: "shop"}
	first, second := base, base
	first.Message = "p99 is 510ms"
	second.Message = "p99 is 530ms"
	if first.Key() != second.Key() {
		t.Error("an alert whose message carries a changing value must keep one dedup key")
	}
}

func TestOneTenantTriggerableWarningNoLongerMasksOtherAgentWarnings(t *testing.T) {
	origEnabled := config.AlertingEnabled
	config.AlertingEnabled = true
	defer func() { config.AlertingEnabled = origEnabled }()

	var mu sync.Mutex
	delivered := map[string]int{}
	m := &Manager{
		enabled: true,
		senders: []Sender{&testMockSender{name: "capture", sendFunc: func(_ context.Context, a *Alert) error {
			mu.Lock()
			defer mu.Unlock()
			delivered[a.Message]++
			return nil
		}}},
		deduplicator: NewAlertDeduplicator(5 * time.Minute),
		rateLimiter:  NewNamespaceRateLimiter(60),
		stopCh:       make(chan struct{}),
	}
	defer SetGlobalManager(nil)
	SetGlobalManager(m)

	const flood = "recovered from panic parsing untrusted binary"
	const unrelated = "could not set kernel aggregation mode"
	for i := 0; i < 5; i++ {
		m.SendAlert(loggerAlert(t, flood))
	}
	m.SendAlert(loggerAlert(t, unrelated))
	if err := m.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if delivered[unrelated] != 1 {
		t.Errorf("the unrelated warning was delivered %d times, want 1", delivered[unrelated])
	}
	if delivered[flood] != 1 {
		t.Errorf("the repeated warning was delivered %d times, want 1 per dedup window", delivered[flood])
	}
}
