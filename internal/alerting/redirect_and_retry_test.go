package alerting

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func redirectAlert() *Alert {
	return &Alert{
		Severity:  SeverityCritical,
		Title:     "t",
		Message:   "m",
		Timestamp: time.Now(),
		Source:    "test",
		PodName:   "pod",
		Namespace: "tenant",
	}
}

type redirectTarget struct {
	server        *httptest.Server
	hits          atomic.Int64
	authorization atomic.Value
}

func newRedirectTarget(t *testing.T) *redirectTarget {
	t.Helper()
	target := &redirectTarget{}
	target.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target.hits.Add(1)
		target.authorization.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.server.Close)
	return target
}

func redirectingReceiver(t *testing.T, to string, code int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to+"/collect?token=secret", code)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAlertSendersDoNotFollowRedirects(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		target := newRedirectTarget(t)
		receiver := redirectingReceiver(t, target.server.URL, code)

		webhook, err := NewWebhookSender(receiver.URL, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		splunk, err := NewSplunkAlertSender(receiver.URL, "hec-token", 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		slack, err := NewSlackSender("https://hooks.slack.com/services/T/B/X", "#alerts", 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		slack.webhookURL = receiver.URL

		for _, sender := range []Sender{webhook, splunk, slack} {
			err := sender.Send(context.Background(), redirectAlert())
			var statusErr *StatusError
			if !errors.As(err, &statusErr) || statusErr.StatusCode != code {
				t.Errorf("%s on %d: err = %v, want a StatusError carrying the redirect", sender.Name(), code, err)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Errorf("%s on %d: the error leaks the redirect's query: %v", sender.Name(), code, err)
			}
		}
		if got := target.hits.Load(); got != 0 {
			t.Errorf("redirect %d: the alert reached the redirect target %d times", code, got)
		}
		if auth, _ := target.authorization.Load().(string); auth != "" {
			t.Errorf("redirect %d: the Splunk token followed the redirect: %q", code, auth)
		}
	}
}

func countingReceiver(t *testing.T, code int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestRetrySenderStopsOnResponsesThatCannotSucceed(t *testing.T) {
	cases := []struct {
		code     int
		attempts int64
	}{
		{http.StatusBadRequest, 1},
		{http.StatusUnauthorized, 1},
		{http.StatusForbidden, 1},
		{http.StatusNotFound, 1},
		{http.StatusRequestEntityTooLarge, 1},
		{http.StatusTemporaryRedirect, 1},
		{http.StatusRequestTimeout, 4},
		{http.StatusTooEarly, 4},
		{http.StatusTooManyRequests, 4},
		{http.StatusInternalServerError, 4},
		{http.StatusServiceUnavailable, 4},
	}
	for _, tc := range cases {
		srv, hits := countingReceiver(t, tc.code)
		webhook, err := NewWebhookSender(srv.URL, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		err = NewRetrySender(webhook, 3, time.Millisecond).Send(context.Background(), redirectAlert())
		if err == nil {
			t.Errorf("status %d: expected an error", tc.code)
		}
		if got := hits.Load(); got != tc.attempts {
			t.Errorf("status %d: %d attempts, want %d", tc.code, got, tc.attempts)
		}
	}
}

func TestStatusErrorKeepsTheExistingMessageShape(t *testing.T) {
	err := &StatusError{StatusCode: 500, Body: "boom"}
	if got := err.Error(); got != "unexpected status code 500: boom" {
		t.Errorf("message = %q", got)
	}
	redirect := &StatusError{StatusCode: 307, Location: "http://other.example"}
	if got := redirect.Error(); got != "unexpected status code 307 (redirect to http://other.example not followed: configure the receiver's final URL)" {
		t.Errorf("redirect message = %q", got)
	}
	bare := &StatusError{StatusCode: 308}
	if got := bare.Error(); got != "unexpected status code 308 (redirect to another location not followed: configure the receiver's final URL)" {
		t.Errorf("redirect without a Location = %q", got)
	}
	if got := (&StatusError{StatusCode: 401, Body: " \n"}).Error(); got != "unexpected status code 401" {
		t.Errorf("empty body message = %q", got)
	}
}
