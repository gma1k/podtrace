package objectstore

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// RetryLogger receives one event per HTTP boundary the SDK crosses for
// a single Upload.
type RetryLogger interface {
	OnAttempt(backend, method, url string, status int, attempt int, took time.Duration, err error)
}

// defaultRetryLogger emits JSON-ish lines to stderr. Kept format-stable
// so log shippers can field-extract (the agent log pipeline already
// expects zap-style fields).
type defaultRetryLogger struct{}

func (defaultRetryLogger) OnAttempt(backend, method, url string, status, attempt int, took time.Duration, err error) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	_, _ = fmt.Fprintf(os.Stderr,
		`{"component":"objectstore.retry","backend":%q,"method":%q,"url":%q,"status":%d,"attempt":%d,"took_ms":%d,"error":%q}`+"\n",
		backend, method, url, status, attempt, took.Milliseconds(), errStr,
	)
}

// redactURL strips query and fragment before logging: presigned S3 URLs
// and Azure SAS tokens carry their credentials in the query string, and a
// retry log line must not leak them to stderr.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	if c.RawQuery != "" {
		c.RawQuery = "REDACTED"
	}
	c.Fragment = ""
	c.User = nil
	return c.String()
}

// loggingTransport is an http.RoundTripper that wraps an inner
// transport with a RetryLogger callback. Used by the S3 and GCS
// backends (both speak HTTP under the SDK).
type loggingTransport struct {
	inner   http.RoundTripper
	backend string
	logger  RetryLogger

	attempts map[string]*atomic.Int32
	mu       sync.Mutex
}

func newLoggingTransport(inner http.RoundTripper, backend string, logger RetryLogger) *loggingTransport {
	if inner == nil {
		inner = http.DefaultTransport
	}
	if logger == nil {
		logger = defaultRetryLogger{}
	}
	return &loggingTransport{
		inner:    inner,
		backend:  backend,
		logger:   logger,
		attempts: map[string]*atomic.Int32{},
	}
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Host + req.URL.Path
	t.mu.Lock()
	counter, ok := t.attempts[key]
	if !ok {
		counter = new(atomic.Int32)
		t.attempts[key] = counter
	}
	t.mu.Unlock()
	attempt := int(counter.Add(1))

	started := time.Now()
	resp, err := t.inner.RoundTrip(req)
	took := time.Since(started)

	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	t.logger.OnAttempt(t.backend, req.Method, redactURL(req.URL), status, attempt, took, err)
	return resp, err
}
