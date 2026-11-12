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
	FailedTraces map[string]struct{}
	SettledSpans map[string]int
	Err          error
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
type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("unexpected status code: %d", e.code) }

// isServerError reports whether the collector answered with a 5xx: it is
// reachable, and the failure may be caused by one payload rather than by
// the collector as a whole.
func isServerError(err error) bool {
	var status *httpStatusError
	return errors.As(err, &status) && status.code >= 500 && status.code <= 599
}

// statusError turns an unexpected HTTP status into an error, marking the
// client errors a backend will keep returning for the same payload as
// permanent. 408 and 429 are retryable by definition.
func statusError(code int) error {
	err := &httpStatusError{code: code}
	if code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests {
		return permanent(err)
	}
	return err
}

// exportOutcome accumulates per-trace results of one ExportTraces call.
type exportOutcome struct {
	failed  map[string]struct{}
	settled map[string]int
	errs    []error
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

func (o *exportOutcome) err() error {
	if len(o.errs) == 0 {
		return nil
	}
	return &PartialExportError{FailedTraces: o.failed, SettledSpans: o.settled, Err: errors.Join(o.errs...)}
}
