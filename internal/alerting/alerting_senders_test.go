package alerting

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestAlert_Clone_Nil(t *testing.T) {
	var a *Alert
	if a.Clone() != nil {
		t.Error("Clone of a nil alert must return nil")
	}
}

func TestAlert_Clone_DeepCopiesContextAndRecommendations(t *testing.T) {
	orig := &Alert{
		Severity:        SeverityWarning,
		Title:           "t",
		Context:         map[string]interface{}{"k": "v"},
		Recommendations: []string{"r1", "r2"},
	}
	cp := orig.Clone()
	if cp == nil {
		t.Fatal("Clone returned nil for a non-nil alert")
	}
	cp.Context["k"] = "mutated"
	cp.Recommendations[0] = "mutated"
	if orig.Context["k"] != "v" {
		t.Error("Context was not deep-copied")
	}
	if orig.Recommendations[0] != "r1" {
		t.Error("Recommendations were not deep-copied")
	}
}

func TestTruncateUTF8_MaxBelowEllipsis(t *testing.T) {
	if got := truncateUTF8("abcd", 2); got != "..." {
		t.Errorf("truncateUTF8(\"abcd\", 2) = %q, want \"...\"", got)
	}
}

func TestTruncateUTF8_BacktracksToRuneBoundary(t *testing.T) {
	got := truncateUTF8("aa€aa", 6)
	if got != "aa..." {
		t.Errorf("truncateUTF8 mid-rune = %q, want \"aa...\" (cut must retreat to a rune boundary)", got)
	}
}

func TestDeduplicator_Forget_Nil(t *testing.T) {
	d := NewAlertDeduplicator(time.Minute)
	d.Forget(nil)
}

func TestDeliveryBudget_CapsPerAttemptBackoff(t *testing.T) {
	origRetries := config.AlertMaxRetries
	defer func() { config.AlertMaxRetries = origRetries }()
	config.AlertMaxRetries = 6

	if got := deliveryBudget(); got <= 0 {
		t.Errorf("deliveryBudget() = %v, want a positive budget", got)
	}
}

func TestNewManager_WebhookCreationError(t *testing.T) {
	origEnabled := config.AlertingEnabled
	origWebhook := config.AlertWebhookURL
	origSlack := config.AlertSlackWebhookURL
	origSplunk := config.AlertSplunkEnabled
	defer func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhook
		config.AlertSlackWebhookURL = origSlack
		config.AlertSplunkEnabled = origSplunk
	}()
	config.AlertingEnabled = true
	config.AlertWebhookURL = "ftp://bad-webhook/endpoint"
	config.AlertSlackWebhookURL = ""
	config.AlertSplunkEnabled = false

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m.IsEnabled() {
		t.Error("a manager with only a failing webhook sender must be disabled")
	}
}

func TestNewManager_SlackSenderAppended(t *testing.T) {
	origEnabled := config.AlertingEnabled
	origWebhook := config.AlertWebhookURL
	origSlack := config.AlertSlackWebhookURL
	origSplunk := config.AlertSplunkEnabled
	defer func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhook
		config.AlertSlackWebhookURL = origSlack
		config.AlertSplunkEnabled = origSplunk
	}()
	config.AlertingEnabled = true
	config.AlertWebhookURL = ""
	config.AlertSlackWebhookURL = "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL"
	config.AlertSplunkEnabled = false

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if !m.IsEnabled() {
		t.Fatal("a valid Slack webhook must yield an enabled manager")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestNewManager_SplunkCreationError(t *testing.T) {
	origEnabled := config.AlertingEnabled
	origWebhook := config.AlertWebhookURL
	origSlack := config.AlertSlackWebhookURL
	origSplunkEnabled := config.AlertSplunkEnabled
	origEndpoint := config.SplunkEndpoint
	origToken := config.SplunkToken
	defer func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhook
		config.AlertSlackWebhookURL = origSlack
		config.AlertSplunkEnabled = origSplunkEnabled
		config.SplunkEndpoint = origEndpoint
		config.SplunkToken = origToken
	}()
	config.AlertingEnabled = true
	config.AlertWebhookURL = ""
	config.AlertSlackWebhookURL = ""
	config.AlertSplunkEnabled = true
	config.SplunkEndpoint = "ftp://bad-splunk/endpoint"
	config.SplunkToken = "token"

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m.IsEnabled() {
		t.Error("a manager with only a failing Splunk sender must be disabled")
	}
}

func TestManager_SendAlert_ShuttingDown(t *testing.T) {
	origEnabled := config.AlertingEnabled
	config.AlertingEnabled = true
	defer func() { config.AlertingEnabled = origEnabled }()

	var called atomic.Bool
	m := &Manager{
		enabled:      true,
		shuttingDown: true,
		senders: []Sender{&testMockSender{sendFunc: func(context.Context, *Alert) error {
			called.Store(true)
			return nil
		}}},
		deduplicator: NewAlertDeduplicator(time.Minute),
		rateLimiter:  NewRateLimiter(60),
	}
	m.SendAlert(&Alert{
		Severity:  SeverityCritical,
		Title:     "t",
		Message:   "m",
		Timestamp: time.Now(),
		Source:    "s",
	})
	time.Sleep(20 * time.Millisecond)
	if called.Load() {
		t.Error("SendAlert must not dispatch to senders once the manager is shutting down")
	}
}

func TestManager_Shutdown_Disabled(t *testing.T) {
	m := &Manager{enabled: false}
	if err := m.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() on a disabled manager = %v, want nil", err)
	}
}

func TestRetrySender_Send_BackoffCappedThenContextDone(t *testing.T) {
	mock := &mockSender{
		sendFunc: func(context.Context, *Alert) error { return errors.New("boom") },
		name:     "mock",
	}
	rs := NewRetrySender(mock, 5, 40*time.Second)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "t",
		Message:   "m",
		Timestamp: time.Now(),
		Source:    "s",
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := rs.Send(ctx, alert)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Send() = %v, want context.Canceled after the capped backoff observes the cancelled context", err)
	}
}

func TestSlackSender_Send_Success200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &SlackSender{
		webhookURL: srv.URL,
		channel:    "#alerts",
		client:     srv.Client(),
		timeout:    2 * time.Second,
	}
	err := s.Send(context.Background(), &Alert{
		Severity:  SeverityWarning,
		Title:     "t",
		Message:   "m",
		Timestamp: time.Now(),
		Source:    "s",
	})
	if err != nil {
		t.Errorf("Send() against a 200 server = %v, want nil", err)
	}
}

func TestSenders_RequestConstructionError(t *testing.T) {
	const badURL = "http://\x7f/collect"
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "t",
		Message:   "m",
		Timestamp: time.Now(),
		Source:    "s",
	}

	slack := &SlackSender{webhookURL: badURL, channel: "#a", client: &http.Client{}, timeout: time.Second}
	if err := slack.Send(context.Background(), alert); err == nil {
		t.Error("slack: expected an error when the request cannot be constructed")
	}

	splunk := &SplunkAlertSender{endpoint: badURL, token: "t", client: &http.Client{}, timeout: time.Second}
	if err := splunk.Send(context.Background(), alert); err == nil {
		t.Error("splunk: expected an error when the request cannot be constructed")
	}

	webhook := &WebhookSender{url: badURL, client: &http.Client{}, timeout: time.Second}
	if err := webhook.Send(context.Background(), alert); err == nil {
		t.Error("webhook: expected an error when the request cannot be constructed")
	}
}

func TestSplunkAlertSender_Send_ReservedContextKeyPrefixed(t *testing.T) {
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body.Store(string(buf))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &SplunkAlertSender{
		endpoint: srv.URL,
		token:    "token",
		client:   srv.Client(),
		timeout:  2 * time.Second,
	}
	err := s.Send(context.Background(), &Alert{
		Severity:  SeverityWarning,
		Title:     "t",
		Message:   "m",
		Timestamp: time.Now(),
		Source:    "s",
		Context:   map[string]interface{}{"severity": "clashing"},
	})
	if err != nil {
		t.Errorf("Send() = %v, want nil", err)
	}
	if got, _ := body.Load().(string); !strings.Contains(got, "ctx_severity") {
		t.Errorf("reserved context key must be prefixed with ctx_, payload=%q", got)
	}
}
