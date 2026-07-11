package logger

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
)

var (
	log         *zap.Logger
	atomicLevel zap.AtomicLevel
)

func init() {
	level := getLogLevel()
	atomicLevel = zap.NewAtomicLevelAt(level)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(os.Stderr),
		atomicLevel,
	)

	log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}

func getLogLevel() zapcore.Level {
	levelStr := os.Getenv("PODTRACE_LOG_LEVEL")
	if levelStr == "" {
		levelStr = config.DefaultLogLevel
	}
	return parseLogLevel(levelStr)
}

func Debug(msg string, fields ...zap.Field) {
	log.Debug(msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	log.Info(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	log.Warn(msg, fields...)
	manager := alerting.GetGlobalManager()
	if manager != nil {
		if alert := alerting.CreateAlertFromLog(zapcore.WarnLevel, msg, fields, "", ""); alert != nil {
			manager.SendAlert(alert)
		}
	}
}

func Error(msg string, fields ...zap.Field) {
	log.Error(msg, fields...)
	manager := alerting.GetGlobalManager()
	if manager != nil {
		if alert := alerting.CreateAlertFromLog(zapcore.ErrorLevel, msg, fields, "", ""); alert != nil {
			manager.SendAlert(alert)
		}
	}
}

func Fatal(msg string, fields ...zap.Field) {
	manager := alerting.GetGlobalManager()
	if manager != nil {
		if alert := alerting.CreateAlertFromLog(zapcore.FatalLevel, msg, fields, "", ""); alert != nil {
			manager.SendAlert(alert)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = manager.Shutdown(ctx)
			cancel()
		}
	}
	log.Fatal(msg, fields...)
}

func Logger() *zap.Logger {
	return log
}

func Sync() {
	_ = log.Sync()
}

func SetLevel(levelStr string) {
	level := parseLogLevel(levelStr)
	atomicLevel.SetLevel(level)
}

func parseLogLevel(levelStr string) zapcore.Level {
	switch levelStr {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}
