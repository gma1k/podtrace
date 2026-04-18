package alerting

import (
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestCreateAlertFromLog_FieldTypes covers the field type branches in
// CreateAlertFromLog: StringType, Int64Type, ErrorType (non-nil), and error_code key.
func TestCreateAlertFromLog_FieldTypes(t *testing.T) {
	m := &Manager{
		enabled:      true,
		senders:      []Sender{},
		deduplicator: NewAlertDeduplicator(10 * time.Minute),
		rateLimiter:  NewRateLimiter(1000),
	}
	orig := globalManager
	SetGlobalManager(m)
	defer SetGlobalManager(orig)

	fields := []zap.Field{
		zap.String("service", "test-service"),           // StringType → context[key]=field.String
		zap.Int64("count", 42),                          // Int64Type  → context[key]=field.Integer
		zap.NamedError("err", errors.New("test error")), // ErrorType non-nil → context[key]=err.Error()
		zap.String("error_code", "E001"),                // error_code key + StringType → errorCode=field.String
	}

	alert := CreateAlertFromLog(zapcore.ErrorLevel, "test message", fields, "pod-1", "default")
	if alert == nil {
		t.Fatal("expected non-nil alert for error level with enabled manager")
	}
	if alert.ErrorCode != "E001" {
		t.Errorf("expected ErrorCode=E001, got %q", alert.ErrorCode)
	}
	if v, ok := alert.Context["service"]; !ok || v != "test-service" {
		t.Errorf("expected context[service]=test-service, got %v", alert.Context["service"])
	}
	if v, ok := alert.Context["count"]; !ok || v != int64(42) {
		t.Errorf("expected context[count]=42, got %v", alert.Context["count"])
	}
	if v, ok := alert.Context["err"]; !ok || v != "test error" {
		t.Errorf("expected context[err]=test error, got %v", alert.Context["err"])
	}
}

// TestCreateAlertFromLog_ErrorType_NilInterface covers the ErrorType branch
// where field.Interface is nil (condition false path — skips body).
func TestCreateAlertFromLog_ErrorType_NilInterface(t *testing.T) {
	m := &Manager{
		enabled:      true,
		senders:      []Sender{},
		deduplicator: NewAlertDeduplicator(10 * time.Minute),
		rateLimiter:  NewRateLimiter(1000),
	}
	orig := globalManager
	SetGlobalManager(m)
	defer SetGlobalManager(orig)

	fields := []zap.Field{
		{Key: "err_nil", Type: zapcore.ErrorType, Interface: nil},
	}
	alert := CreateAlertFromLog(zapcore.ErrorLevel, "nil error test", fields, "pod-2", "ns")
	if alert == nil {
		t.Fatal("expected non-nil alert")
	}
	if _, ok := alert.Context["err_nil"]; ok {
		t.Error("expected err_nil NOT to be in context when interface is nil")
	}
}

// TestCreateAlertFromLog_CodeKeyAlias covers the "code" key alias for error_code (line 59).
func TestCreateAlertFromLog_CodeKeyAlias(t *testing.T) {
	m := &Manager{
		enabled:      true,
		senders:      []Sender{},
		deduplicator: NewAlertDeduplicator(10 * time.Minute),
		rateLimiter:  NewRateLimiter(1000),
	}
	orig := globalManager
	SetGlobalManager(m)
	defer SetGlobalManager(orig)

	fields := []zap.Field{
		zap.String("code", "CODE42"),
	}
	alert := CreateAlertFromLog(zapcore.WarnLevel, "warn with code", fields, "pod-3", "ns")
	if alert == nil {
		t.Fatal("expected non-nil alert")
	}
	if alert.ErrorCode != "CODE42" {
		t.Errorf("expected ErrorCode=CODE42 via 'code' key, got %q", alert.ErrorCode)
	}
}

// TestCreateAlertFromLog_Int32Type covers the Int32Type case body (same branch as Int64Type).
func TestCreateAlertFromLog_Int32Type(t *testing.T) {
	m := &Manager{
		enabled:      true,
		senders:      []Sender{},
		deduplicator: NewAlertDeduplicator(10 * time.Minute),
		rateLimiter:  NewRateLimiter(1000),
	}
	orig := globalManager
	SetGlobalManager(m)
	defer SetGlobalManager(orig)

	fields := []zap.Field{
		zap.Int32("retry", 3),
	}
	alert := CreateAlertFromLog(zapcore.ErrorLevel, "int32 test", fields, "pod-4", "ns")
	if alert == nil {
		t.Fatal("expected non-nil alert")
	}
	if v, ok := alert.Context["retry"]; !ok || v != int64(3) {
		t.Errorf("expected context[retry]=3, got %v", alert.Context["retry"])
	}
}
