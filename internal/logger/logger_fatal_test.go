package logger

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
)

func newGoexitFatalLogger(w *bytes.Buffer) *zap.Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(w),
		zapcore.DebugLevel,
	)
	return zap.New(core, zap.WithFatalHook(zapcore.WriteThenGoexit))
}

func runFatal(t *testing.T, msg string, fields ...zap.Field) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Fatal(msg, fields...)
	}()
	<-done
}

func TestFatal_WritesMessage(t *testing.T) {
	origLog := log
	t.Cleanup(func() { log = origLog })

	origMgr := alerting.GetGlobalManager()
	t.Cleanup(func() { alerting.SetGlobalManager(origMgr) })
	alerting.SetGlobalManager(nil)

	var buf bytes.Buffer
	log = newGoexitFatalLogger(&buf)

	runFatal(t, "fatal without manager", zap.String("k", "v"))

	out := buf.String()
	if !strings.Contains(out, "fatal without manager") {
		t.Errorf("Fatal output %q does not contain the message", out)
	}
	if !strings.Contains(out, "fatal") {
		t.Errorf("Fatal output %q does not carry the fatal level", out)
	}
}

func TestFatal_WithAlertingManager(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	origEnabled := config.AlertingEnabled
	origWebhookURL := config.AlertWebhookURL
	origMinSev := config.GetAlertMinSeverity()
	origMgr := alerting.GetGlobalManager()
	t.Cleanup(func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhookURL
		_ = os.Setenv("PODTRACE_ALERT_MIN_SEVERITY", origMinSev)
		alerting.SetGlobalManager(origMgr)
	})

	config.AlertingEnabled = true
	config.AlertWebhookURL = srv.URL
	_ = os.Setenv("PODTRACE_ALERT_MIN_SEVERITY", "warning")

	manager, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !manager.IsEnabled() {
		t.Skip("manager disabled (no senders configured) — skipping alerting Fatal path")
	}
	alerting.SetGlobalManager(manager)

	origLog := log
	t.Cleanup(func() { log = origLog })
	var buf bytes.Buffer
	log = newGoexitFatalLogger(&buf)

	runFatal(t, "fatal with manager", zap.String("ctx", "test"))

	if out := buf.String(); !strings.Contains(out, "fatal with manager") {
		t.Errorf("Fatal output %q does not contain the message", out)
	}
}
