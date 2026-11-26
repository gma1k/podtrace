package exporter

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gma1k/podtrace/internal/netguard"
)

// PartialExportError reports an export that did not deliver a whole batch.
// FailedTraces names the traces that hit a transient failure and must be
// offered again.
type PartialExportError struct {
	FailedTraces  map[string]struct{}
	SettledSpans  map[string]int
	RejectedSpans int64
	Err           error
}

func (e *PartialExportError) Error() string { return e.Err.Error() }

func (e *PartialExportError) Unwrap() error { return e.Err }

// Retry reports whether the trace must be offered to the exporter again.
func (e *PartialExportError) Retry(traceID string) bool {
	_, ok := e.FailedTraces[traceID]
	return ok
}

// SettledPrefix returns how many leading spans of a retried trace the
// exporter already settled, because the trace was split across requests and
// the earlier ones went through. Only the spans after them are offered again.
func (e *PartialExportError) SettledPrefix(traceID string) int {
	return e.SettledSpans[traceID]
}

// RejectedSpansError reports an export the collector accepted in full
// while rejecting some of its spans (an OTLP partial success).
type RejectedSpansError struct {
	Spans int64
	Err   error
}

func (e *RejectedSpansError) Error() string {
	return fmt.Sprintf("collector rejected %d spans: %v", e.Spans, e.Err)
}

func (e *RejectedSpansError) Unwrap() error { return e.Err }

// RejectedSpans returns how many spans the collector accepted the request
// for but rejected, as reported by err.
func RejectedSpans(err error) int64 {
	var rejected *RejectedSpansError
	if errors.As(err, &rejected) {
		return rejected.Spans
	}
	var partial *PartialExportError
	if errors.As(err, &partial) {
		return partial.RejectedSpans
	}
	return 0
}

// permanentError marks a failure that resending the same payload cannot fix.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }

func (e *permanentError) Unwrap() error { return e.err }

func permanent(err error) error {
	return &permanentError{err: err}
}

// isPermanent also treats an egress-guard refusal as permanent: the guard
// refuses the same destination on every attempt, so retrying would only
// pile the batch up until the traces expire.
func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p) || errors.Is(err, netguard.ErrBlocked)
}

// httpStatusError is a collector's answer with an unexpected HTTP status.
// detail is what the client library reported about it, if anything.
type httpStatusError struct {
	code   int
	detail error
}

func (e *httpStatusError) Error() string {
	if e.detail != nil {
		return fmt.Sprintf("unexpected status code: %d: %v", e.code, e.detail)
	}
	return fmt.Sprintf("unexpected status code: %d", e.code)
}

func (e *httpStatusError) Unwrap() error { return e.detail }

// isServerError reports whether the collector answered with a 5xx that may
// be caused by one payload rather than by the collector as a whole. 502,
// 503 and 504 are left out: a gateway or an overloaded collector answers
// them whatever the payload, so they are retried like a 429.
func isServerError(err error) bool {
	if isGRPCServerError(err) {
		return true
	}
	var status *httpStatusError
	if !errors.As(err, &status) || status.code < 500 || status.code > 599 {
		return false
	}
	switch status.code {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return false
	}
	return true
}

// isTooLarge reports whether the collector refused the request body as too
// large; a smaller request may still be accepted.
func isTooLarge(err error) bool {
	var status *httpStatusError
	return errors.As(err, &status) && status.code == http.StatusRequestEntityTooLarge
}

// isSplittable reports whether splitting the failed batch can get part of
// it delivered.
func isSplittable(err error) bool {
	return isServerError(err) || isTooLarge(err)
}

// statusError turns an unexpected HTTP status into an error, marking the
// client errors a backend will keep returning for the same payload as
// permanent. 408 and 429 are retryable by definition.
func statusError(code int) error {
	return statusErrorDetail(code, nil)
}

// statusErrorDetail is statusError keeping what the client library
// reported about the answer.
func statusErrorDetail(code int, detail error) error {
	err := &httpStatusError{code: code, detail: detail}
	if code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests {
		return permanent(err)
	}
	return err
}

// exportOutcome accumulates per-trace results of one ExportTraces call.
type exportOutcome struct {
	failed    map[string]struct{}
	settled   map[string]int
	errs      []error
	rejected  int64
	rejection error
}

// record notes err against the given traces; transient errors schedule
// them for retry, permanent ones are reported but not retried.
func (o *exportOutcome) record(err error, traceIDs ...string) {
	if err == nil {
		return
	}
	o.errs = append(o.errs, err)
	if isPermanent(err) {
		return
	}
	o.retry(traceIDs...)
}

// retry schedules traces that were never sent for the next export, without
// reporting an error of their own.
func (o *exportOutcome) retry(traceIDs ...string) {
	if o.failed == nil {
		o.failed = make(map[string]struct{}, len(traceIDs))
	}
	for _, id := range traceIDs {
		o.failed[id] = struct{}{}
	}
}

// settle notes that spans more of the trace's leading spans were delivered
// or permanently refused.
func (o *exportOutcome) settle(traceID string, spans int) {
	if o.settled == nil {
		o.settled = make(map[string]int)
	}
	o.settled[traceID] += spans
}

// reject notes spans the collector rejected in a request it accepted.
func (o *exportOutcome) reject(spans int64, err error) {
	if spans <= 0 {
		return
	}
	o.rejected += spans
	o.rejection = err
}

func (o *exportOutcome) err() error {
	if len(o.errs) == 0 {
		if o.rejected > 0 {
			return &RejectedSpansError{Spans: o.rejected, Err: o.rejection}
		}
		return nil
	}
	return &PartialExportError{FailedTraces: o.failed, SettledSpans: o.settled, RejectedSpans: o.rejected, Err: errors.Join(o.errs...)}
}
