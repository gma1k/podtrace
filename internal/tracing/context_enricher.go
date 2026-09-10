package tracing

import (
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/tracing/extractor"
)

type ContextEnricher struct {
	extractor  *extractor.HTTPExtractor
	corr       *correlationCache
	synthesize bool
}

// NewContextEnricher builds an enricher.
func NewContextEnricher() *ContextEnricher {
	return &ContextEnricher{
		extractor:  extractor.NewHTTPExtractor(),
		corr:       newCorrelationCache(config.MaxTraceContextCacheSize),
		synthesize: config.SynthesizeSpans,
	}
}

// Enrich populates TraceID, SpanID and the surrounding context on an event,
// reporting whether the event now carries a trace identity.
func (c *ContextEnricher) Enrich(event *events.Event) bool {
	if c == nil || event == nil {
		return false
	}

	if event.Details != "" {
		if tc := c.extractor.ExtractFromRawHeaders(event.Details); tc != nil && tc.HasRemoteParent() {
			event.TraceID = tc.TraceID
			event.ParentSpanID = tc.ParentSpanID
			event.TraceFlags = tc.Flags
			event.TraceState = tc.State

			if isCorrelatableL7(event) {
				key := correlationKey(event)
				event.SpanID = deriveSpanID(key)
				c.corr.store(key, correlationEntry{
					traceID:      event.TraceID,
					parentSpanID: event.ParentSpanID,
					spanID:       event.SpanID,
					flags:        event.TraceFlags,
					state:        event.TraceState,
				})
			} else {
				event.SpanID = deriveSpanID(event.TraceID + event.ParentSpanID)
			}
			return true
		}
	}

	if !isCorrelatableL7(event) {
		return false
	}

	key := correlationKey(event)
	if e, ok := c.corr.loadDelete(key); ok {
		event.TraceID = e.traceID
		event.ParentSpanID = e.parentSpanID
		event.SpanID = e.spanID
		event.TraceFlags = e.flags
		event.TraceState = e.state
		return true
	}

	if c.synthesize {
		event.TraceID = deriveTraceID(key)
		event.SpanID = deriveSpanID(key)
		return true
	}
	return false
}
