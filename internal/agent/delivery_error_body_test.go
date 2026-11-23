package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const internalServiceSecret = "internal-admin-token-7f3a"

func TestDeliveryErrorWithholdsTheBodyOfARealOTLPRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"service":"billing","token":"` + internalServiceSecret + `"}`))
	}))
	defer srv.Close()

	exporter, err := newOTLPSpanExporter(&BundlePayload{Endpoint: srv.URL, Insecure: true})
	if err != nil {
		t.Fatalf("newOTLPSpanExporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()

	stub := tracetest.SpanStub{Name: "probe", StartTime: time.Now(), EndTime: time.Now()}
	exportErr := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{stub.Snapshot()})
	if exportErr == nil {
		t.Fatal("export to a 404 endpoint succeeded")
	}
	if !strings.Contains(exportErr.Error(), internalServiceSecret) {
		t.Fatalf("precondition: the OTLP client no longer echoes the body (%q); the withholding may be unnecessary", exportErr)
	}

	text := deliveryErrorText(exportErr)
	if strings.Contains(text, internalServiceSecret) || strings.Contains(text, "billing") {
		t.Errorf("delivery error leaks the response body: %q", text)
	}
	if !strings.Contains(text, "404 Not Found") {
		t.Errorf("delivery error lost the status line: %q", text)
	}
	if !strings.HasSuffix(text, "(response body withheld)") {
		t.Errorf("delivery error = %q, want it to end with the balanced withheld marker", text)
	}
}

func TestDeliveryErrorWithholdsTheBodyOfARetryableRejection(t *testing.T) {
	err := errors.New("retry-able request failure: body: <html>" + internalServiceSecret + "</html>")
	got := deliveryErrorText(err)
	if want := "retry-able request failure: response body withheld"; got != want {
		t.Errorf("deliveryErrorText = %q, want %q", got, want)
	}
}

func TestDeliveryErrorKeepsErrorsWithoutABody(t *testing.T) {
	err := errors.New("dial tcp 10.0.0.7:4318: connect: connection refused")
	if got := deliveryErrorText(err); got != err.Error() {
		t.Errorf("deliveryErrorText = %q, want it unchanged", got)
	}
}

func TestDeliveryHealthStoresTheWithheldForm(t *testing.T) {
	h := newDeliveryHealth()
	owner := &struct{}{}
	h.register(deliveryCR, owner)
	h.fail(deliveryCR, owner, "otlp", errors.New("failed to send: 500 Internal Server Error (body: "+internalServiceSecret+")"), time.Now())

	state, failing := h.failing(deliveryCR)
	if !failing {
		t.Fatal("failure not recorded")
	}
	if strings.Contains(state.LastError, internalServiceSecret) {
		t.Errorf("LastError, which reaches PodTrace status, leaks the body: %q", state.LastError)
	}
	if state.LastError != "failed to send: 500 Internal Server Error (response body withheld)" {
		t.Errorf("LastError = %q", state.LastError)
	}
}
