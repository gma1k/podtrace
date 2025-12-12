package alerting

import (
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalManager *Manager
	managerMu     sync.RWMutex
)

func SetGlobalManager(manager *Manager) {
	managerMu.Lock()
	defer managerMu.Unlock()
	globalManager = manager
}

func GetGlobalManager() *Manager {
	managerMu.RLock()
	defer managerMu.RUnlock()
	return globalManager
}

func CreateAlertFromLog(level zapcore.Level, msg string, fields []zap.Field, podName, namespace string) *Alert {
	managerMu.RLock()
	manager := globalManager
	managerMu.RUnlock()
	if manager == nil || !manager.IsEnabled() {
		return nil
	}
	var severity AlertSeverity
	switch level {
	case zapcore.FatalLevel:
		severity = SeverityFatal
	case zapcore.ErrorLevel:
		severity = SeverityError
	case zapcore.WarnLevel:
		severity = SeverityWarning
	default:
		return nil
	}
	context := make(map[string]interface{})
	errorCode := ""
	for _, field := range fields {
		switch field.Type {
		case zapcore.StringType:
			context[field.Key] = field.String
		case zapcore.Int64Type, zapcore.Int32Type:
			context[field.Key] = field.Integer
		case zapcore.ErrorType:
			if field.Interface != nil {
				context[field.Key] = field.Interface.(error).Error()
			}
		}
		if field.Key == "error_code" || field.Key == "code" {
			if field.Type == zapcore.StringType {
				errorCode = field.String
			}
		}
	}
	alert := &Alert{
		Severity:  severity,
		Title:     "Podtrace " + level.String() + " Error",
		Message:   msg,
		Timestamp: time.Now(),
		Source:    "logger",
		PodName:   podName,
		Namespace: namespace,
		Context:   context,
		ErrorCode: errorCode,
	}
	return alert
}

