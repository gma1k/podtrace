package logger

import (
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/sanitize"
)

const (
	otelErrorInterval = time.Minute

	otelErrorKeys = 256
)

// otelErrorHandler logs the errors the OpenTelemetry SDK reports outside a
// caller's return value: failed span batches and metric pushes. Without it
// the SDK prints them with the standard library logger, unredacted, on
// every batch, response body included, so whatever a tenant-chosen
// endpoint answered landed in the agent and session logs. The text is
// redacted the way delivery failures are, and each message is logged at
// most once per interval. Info, not Warn: Warn raises alerts, and the
// failing delivery is already reported on the PodTrace status and by the
// exporter's own warning.
type otelErrorHandler struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
	log  func(msg string, fields ...zap.Field)
}

func newOTelErrorHandler() *otelErrorHandler {
	return &otelErrorHandler{last: map[string]time.Time{}, now: time.Now, log: Info}
}

func (h *otelErrorHandler) Handle(err error) {
	if err == nil {
		return
	}
	text := sanitize.WithholdResponseBody(alerting.RedactURLsInText(err.Error()))
	now := h.now()

	h.mu.Lock()
	if at, seen := h.last[text]; seen && now.Sub(at) < otelErrorInterval {
		h.mu.Unlock()
		return
	}
	if len(h.last) >= otelErrorKeys {
		h.last = map[string]time.Time{}
	}
	h.last[text] = now
	h.mu.Unlock()

	h.log("OpenTelemetry export error", zap.String("error", text))
}

// InstallOTelErrorHandler routes the OpenTelemetry SDK's background errors
// through the podtrace logger.
func InstallOTelErrorHandler() {
	otel.SetErrorHandler(newOTelErrorHandler())
}
