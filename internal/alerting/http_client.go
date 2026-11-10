package alerting

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// newAlertHTTPClient returns the client every HTTP alert sender uses. It never
// follows a redirect: a 307/308 would replay the alert body, and the Splunk
// token with it, to a location that was never validated, including an
// https-to-http downgrade on the same host.
func newAlertHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// StatusError is a receiver's non-success HTTP response.
type StatusError struct {
	StatusCode int
	Body       string
	Location   string
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("unexpected status code %d", e.StatusCode)
	if body := strings.TrimSpace(e.Body); body != "" {
		msg += ": " + body
	}
	if e.StatusCode >= 300 && e.StatusCode < 400 {
		target := e.Location
		if target == "" {
			target = "another location"
		}
		msg += fmt.Sprintf(" (redirect to %s not followed: configure the receiver's final URL)", target)
	}
	return msg
}

// Retryable reports whether the same request could succeed later. A redirect
// or a 4xx (a wrong token, a rejected payload, a missing route) will not, so
// retrying only burns the delivery budget; timeouts, throttling and server
// errors can.
func (e *StatusError) Retryable() bool {
	switch e.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	}
	return e.StatusCode >= 500
}

// statusErrorFrom reads a bounded, URL-redacted excerpt of a failed response.
func statusErrorFrom(resp *http.Response) *StatusError {
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	location := ""
	if raw := resp.Header.Get("Location"); raw != "" {
		location = redactURLForLog(raw)
	}
	return &StatusError{
		StatusCode: resp.StatusCode,
		Body:       RedactURLsInText(string(bodyBytes)),
		Location:   location,
	}
}
