package logger

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
)

func TestLogger(t *testing.T) {
	log := Logger()
	if log == nil {
		t.Error("Logger() should not return nil")
	}
}

func TestSetLevel(t *testing.T) {
	originalLevel := atomicLevel.Level()
	defer SetLevel(originalLevel.String())

	tests := []struct {
		name     string
		levelStr string
		expected zapcore.Level
	}{
		{"debug", "debug", zapcore.DebugLevel},
		{"info", "info", zapcore.InfoLevel},
		{"warn", "warn", zapcore.WarnLevel},
		{"error", "error", zapcore.ErrorLevel},
		{"fatal", "fatal", zapcore.FatalLevel},
		{"invalid", "invalid", zapcore.InfoLevel},
		{"empty", "", zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetLevel(tt.levelStr)
			if atomicLevel.Level() != tt.expected {
				t.Errorf("Expected level %v, got %v", tt.expected, atomicLevel.Level())
			}
		})
	}
}

func TestLogFunctions(t *testing.T) {
	SetLevel("debug")

	Debug("test debug message", zap.String("key", "value"))
	Info("test info message", zap.String("key", "value"))
	Warn("test warn message", zap.String("key", "value"))
	Error("test error message", zap.String("key", "value"))
}


func TestSync(t *testing.T) {
	Sync()
}

// TestWarnAndError_WithAlertingManager exercises the alerting branch in Warn and Error.
// It spins up a dummy HTTP server as the webhook endpoint so the manager has a real sender.
func TestWarnAndError_WithAlertingManager(t *testing.T) {
	// Dummy HTTP server that accepts any POST.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Temporarily configure alerting.
	origEnabled := config.AlertingEnabled
	origWebhookURL := config.AlertWebhookURL
	origMinSev := config.GetAlertMinSeverity()
	t.Cleanup(func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhookURL
		_ = os.Setenv("PODTRACE_ALERT_MIN_SEVERITY", origMinSev)
		alerting.SetGlobalManager(nil)
	})

	config.AlertingEnabled = true
	config.AlertWebhookURL = srv.URL
	_ = os.Setenv("PODTRACE_ALERT_MIN_SEVERITY", "warning")

	manager, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !manager.IsEnabled() {
		t.Skip("manager disabled (no senders configured) — skipping alerting path test")
	}
	alerting.SetGlobalManager(manager)

	// These calls now go through the manager != nil branch.
	Warn("test warn with manager", zap.String("ctx", "test"))
	Error("test error with manager", zap.String("ctx", "test"))
}

func TestParseLogLevel(t *testing.T) {
	key := "PODTRACE_LOG_LEVEL"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	tests := []struct {
		name     string
		levelStr string
		expected zapcore.Level
	}{
		{"debug", "debug", zapcore.DebugLevel},
		{"info", "info", zapcore.InfoLevel},
		{"warn", "warn", zapcore.WarnLevel},
		{"error", "error", zapcore.ErrorLevel},
		{"fatal", "fatal", zapcore.FatalLevel},
		{"invalid", "invalid", zapcore.InfoLevel},
		{"uppercase", "DEBUG", zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogLevel(tt.levelStr)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}


