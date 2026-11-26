package exporter

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// otlpResponse records the HTTP status the collector answered an OTLP
// export with. The OTLP client folds most statuses into error text.
type otlpResponse struct {
	status atomic.Int32
}

func (r *otlpResponse) statusCode() int {
	if r == nil {
		return 0
	}
	return int(r.status.Load())
}

type otlpResponseKey struct{}

func withOTLPResponse(ctx context.Context, r *otlpResponse) context.Context {
	return context.WithValue(ctx, otlpResponseKey{}, r)
}

// responseRecordingTransport notes each response's status in the
// otlpResponse carried by the request's context.
type responseRecordingTransport struct {
	base http.RoundTripper
}

func recordOTLPResponse(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return responseRecordingTransport{base: base}
}

func (t responseRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp != nil {
		if r, ok := req.Context().Value(otlpResponseKey{}).(*otlpResponse); ok {
			r.record(resp.StatusCode)
		}
	}
	return resp, err
}

// HTTP status codes are three digits (RFC 9110 section 15).
const (
	minHTTPStatusCode = 100
	maxHTTPStatusCode = 999
)

// record keeps code when it is a valid HTTP status; anything else is not a
// status the collector can have answered with, so it is left unrecorded.
func (r *otlpResponse) record(code int) {
	if code < minHTTPStatusCode || code > maxHTTPStatusCode {
		return
	}
	r.status.Store(int32(code))
}

// grpcStatusError is an OTLP/gRPC answer that, like an HTTP 500, may be
// caused by one payload rather than by the collector as a whole.
type grpcStatusError struct {
	code codes.Code
	err  error
}

func (e *grpcStatusError) Error() string { return e.err.Error() }

func (e *grpcStatusError) Unwrap() error { return e.err }

// classifyGRPCError sorts a gRPC status the way statusError sorts HTTP
// statuses: requests the collector will refuse again are permanent,
// Internal and Unknown may be caused by one payload and are isolated, and
// the rest (Unavailable, ResourceExhausted, DeadlineExceeded, ...) are
// retried as a whole.
func classifyGRPCError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.PermissionDenied,
		codes.FailedPrecondition, codes.Unimplemented, codes.Unauthenticated:
		return permanent(err)
	case codes.Internal, codes.Unknown:
		return &grpcStatusError{code: st.Code(), err: err}
	}
	return err
}

func isGRPCServerError(err error) bool {
	var g *grpcStatusError
	return errors.As(err, &g)
}
