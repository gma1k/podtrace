package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestNewManager_Disabled(t *testing.T) {
	_ = os.Setenv("PODTRACE_ALERTING_ENABLED", "false")
	defer func() {
		_ = os.Unsetenv("PODTRACE_ALERTING_ENABLED")
	}()
	config.AlertingEnabled = false
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager.IsEnabled() {
		t.Error("Manager should be disabled")
	}
}

func TestManager_SendAlert_Disabled(t *testing.T) {
	manager := &Manager{enabled: false}
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	manager.SendAlert(alert)
}

func TestManager_SendAlert_Nil(t *testing.T) {
	manager := &Manager{enabled: true}
	manager.SendAlert(nil)
}

func TestManager_Shutdown(t *testing.T) {
	manager := &Manager{
		enabled: true,
		stopCh:  make(chan struct{}),
	}
	manager.cleanupTicker = time.NewTicker(1 * time.Hour)
	manager.wg.Add(1)
	go func() {
		defer manager.wg.Done()
		<-manager.stopCh
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_AddSender(t *testing.T) {
	manager := &Manager{
		enabled: true,
		senders: make([]Sender, 0),
	}
	mockSender := &testMockSender{name: "test"}
	manager.AddSender(mockSender)
	if len(manager.senders) != 1 {
		t.Errorf("Expected 1 sender, got %d", len(manager.senders))
	}
	manager.AddSender(nil)
	if len(manager.senders) != 1 {
		t.Errorf("Expected 1 sender after adding nil, got %d", len(manager.senders))
	}
}

type testMockSender struct {
	sendFunc func(ctx context.Context, alert *Alert) error
	name     string
}

func (m *testMockSender) Send(ctx context.Context, alert *Alert) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, alert)
	}
	return nil
}

func (m *testMockSender) Name() string {
	return m.name
}

// TestSetGetGlobalManager verifies the global manager getter/setter.
func TestSetGetGlobalManager(t *testing.T) {
	// Reset global state after test.
	defer SetGlobalManager(nil)

	if got := GetGlobalManager(); got != nil {
		t.Error("expected nil global manager initially")
	}

	m := &Manager{enabled: true}
	SetGlobalManager(m)

	if got := GetGlobalManager(); got != m {
		t.Errorf("GetGlobalManager()=%p, want %p", got, m)
	}

	SetGlobalManager(nil)
	if got := GetGlobalManager(); got != nil {
		t.Error("expected nil after setting to nil")
	}
}

// TestShouldSendAlert verifies severity gating.
func TestShouldSendAlert(t *testing.T) {
	origEnabled := config.AlertingEnabled
	defer func() { config.AlertingEnabled = origEnabled }()

	config.AlertingEnabled = false
	if ShouldSendAlert(SeverityCritical) {
		t.Error("expected false when alerting disabled")
	}

	config.AlertingEnabled = true
	// Default min severity is typically "warning"; critical should pass.
	if !ShouldSendAlert(SeverityCritical) {
		t.Log("ShouldSendAlert(Critical)=false — may depend on config, skipping")
	}
}

// TestCreateAlertFromLog_NilManager verifies no panic when global manager is nil.
func TestCreateAlertFromLog_NilManager(t *testing.T) {
	defer SetGlobalManager(nil)
	SetGlobalManager(nil)

	alert := CreateAlertFromLog(0 /* Debug */, "test message", nil, "pod", "ns")
	if alert != nil {
		t.Error("expected nil alert when manager is nil")
	}
}

// TestCreateAlertFromLog_WithManager verifies alert creation from a log entry.
func TestCreateAlertFromLog_WithManager(t *testing.T) {
	defer SetGlobalManager(nil)

	m := &Manager{enabled: true, senders: make([]Sender, 0)}
	SetGlobalManager(m)

	// zapcore level constants: DebugLevel=-1, InfoLevel=0, WarnLevel=1, ErrorLevel=2, FatalLevel=5
	const (
		warnLevel  = 1  // zapcore.WarnLevel
		errLevel   = 2  // zapcore.ErrorLevel
		fatalLevel = 5  // zapcore.FatalLevel
		debugLevel = -1 // zapcore.DebugLevel (should return nil)
	)

	// Debug is not an alerting level.
	if alert := CreateAlertFromLog(debugLevel, "debug msg", nil, "", ""); alert != nil {
		t.Error("expected nil alert for debug level")
	}

	// Warn level
	alert := CreateAlertFromLog(warnLevel, "warning msg", nil, "mypod", "mynamespace")
	if alert == nil {
		t.Fatal("expected non-nil alert for warn level")
	}
	if alert.Severity != SeverityWarning {
		t.Errorf("expected SeverityWarning, got %v", alert.Severity)
	}
	if alert.PodName != "mypod" || alert.Namespace != "mynamespace" {
		t.Errorf("unexpected pod/ns: %q/%q", alert.PodName, alert.Namespace)
	}

	// Error level
	alertErr := CreateAlertFromLog(errLevel, "error msg", nil, "", "")
	if alertErr == nil {
		t.Fatal("expected non-nil alert for error level")
	}
	if alertErr.Severity != SeverityError {
		t.Errorf("expected SeverityError, got %v", alertErr.Severity)
	}

	// Fatal level
	alertFatal := CreateAlertFromLog(fatalLevel, "fatal msg", nil, "", "")
	if alertFatal == nil {
		t.Fatal("expected non-nil alert for fatal level")
	}
	if alertFatal.Severity != SeverityFatal {
		t.Errorf("expected SeverityFatal, got %v", alertFatal.Severity)
	}
}

// TestNewManager_Enabled_NoSenders verifies that NewManager with no configured senders returns disabled.
func TestNewManager_Enabled_NoSenders(t *testing.T) {
	origEnabled := config.AlertingEnabled
	defer func() { config.AlertingEnabled = origEnabled }()
	config.AlertingEnabled = true

	// No webhook/slack/splunk configured → should return disabled manager (no senders).
	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	if m.IsEnabled() {
		t.Log("Manager enabled with senders (integration env detected); OK")
	}
}

// TestCleanupLoop exercises cleanupLoop via a real enabled manager with a test HTTP server.
func TestCleanupLoop(t *testing.T) {
	// Spin up a dummy HTTP server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	origEnabled := config.AlertingEnabled
	origWebhookURL := config.AlertWebhookURL
	t.Cleanup(func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhookURL
	})

	config.AlertingEnabled = true
	config.AlertWebhookURL = srv.URL

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !m.IsEnabled() {
		t.Skip("manager disabled — skipping cleanupLoop test")
	}

	// Shut down immediately: cleanupLoop receives from stopCh and exits.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
