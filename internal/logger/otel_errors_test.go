package logger

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type recordedLog struct {
	msg   string
	error string
}

func recordingHandler(at *time.Time) (*otelErrorHandler, *[]recordedLog) {
	var got []recordedLog
	h := newOTelErrorHandler()
	h.now = func() time.Time { return *at }
	h.log = func(msg string, fields ...zap.Field) {
		rec := recordedLog{msg: msg}
		for _, f := range fields {
			if f.Key == "error" {
				rec.error = f.String
			}
		}
		got = append(got, rec)
	}
	return h, &got
}

const tenantEndpointBody = `{"internal":"billing-admin","token":"INTERNAL-SECRET-7f3a9c"}`

func TestOTelErrorsWithholdTheResponseBody(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	h, got := recordingHandler(&at)
	h.Handle(errors.New("traces export: failed to send to http://leak.observability:4318/v1/traces?key=abc: 404 Not Found (body: " + tenantEndpointBody + ")"))

	if len(*got) != 1 {
		t.Fatalf("logged %d times, want 1", len(*got))
	}
	text := (*got)[0].error
	if strings.Contains(text, "INTERNAL-SECRET") || strings.Contains(text, "billing-admin") {
		t.Errorf("the SDK error log leaks the endpoint's response body: %q", text)
	}
	if strings.Contains(text, "key=abc") {
		t.Errorf("the SDK error log leaks the URL query: %q", text)
	}
	if !strings.Contains(text, "404 Not Found (response body withheld)") {
		t.Errorf("logged %q, want the status line kept", text)
	}
}

func TestOTelErrorsAreLoggedOncePerInterval(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	h, got := recordingHandler(&at)
	failure := errors.New("traces export: connection refused")

	for i := 0; i < 30; i++ {
		h.Handle(failure)
		at = at.Add(2 * time.Second)
	}
	if len(*got) != 1 {
		t.Fatalf("a failure repeated every 2s for a minute was logged %d times, want 1", len(*got))
	}

	at = at.Add(otelErrorInterval)
	h.Handle(failure)
	if len(*got) != 2 {
		t.Fatalf("the failure was not logged again after the interval: %d", len(*got))
	}

	h.Handle(errors.New("metrics export: deadline exceeded"))
	if len(*got) != 3 {
		t.Fatalf("a different failure was suppressed: %d", len(*got))
	}
}

func TestOTelErrorMemoryIsBounded(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	h, _ := recordingHandler(&at)
	for i := 0; i < otelErrorKeys*3; i++ {
		h.Handle(errors.New(strings.Repeat("x", i%7) + time.Duration(i).String()))
	}
	if len(h.last) > otelErrorKeys {
		t.Errorf("remembered %d distinct errors, want at most %d", len(h.last), otelErrorKeys)
	}
}

func TestOTelErrorHandlerIgnoresNil(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	h, got := recordingHandler(&at)
	h.Handle(nil)
	if len(*got) != 0 {
		t.Errorf("a nil error was logged")
	}
}

func TestInstalledHandlerReceivesTheSDKErrors(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	prevLog := log
	log = zap.New(core)
	t.Cleanup(func() { log = prevLog })

	InstallOTelErrorHandler()
	otel.Handle(errors.New("traces export: 500 Internal Server Error (body: " + tenantEndpointBody + ")"))

	entries := logs.FilterMessage("OpenTelemetry export error").All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries from otel.Handle, want 1", len(entries))
	}
	if entries[0].Level != zapcore.InfoLevel {
		t.Errorf("logged at %v, want info so it does not raise alerts", entries[0].Level)
	}
	if text := entries[0].ContextMap()["error"]; strings.Contains(text.(string), "INTERNAL-SECRET") {
		t.Errorf("the installed handler leaks the body: %v", text)
	}
}
