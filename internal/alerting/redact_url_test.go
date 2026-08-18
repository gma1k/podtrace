package alerting

import (
	"fmt"
	"strings"
	"testing"
)

func TestRedactURLForLog_StripsUserinfoAndQuery(t *testing.T) {
	got := RedactURLForLog("https://user:s3cret@collector.example.com:8088/services/collector?token=abc123")
	if got != "https://collector.example.com:8088" {
		t.Fatalf("RedactURLForLog = %q, want https://collector.example.com:8088", got)
	}
	for _, leak := range []string{"s3cret", "token", "abc123", "user"} {
		if strings.Contains(got, leak) {
			t.Errorf("RedactURLForLog leaked %q: %s", leak, got)
		}
	}
}

func TestRedactURLsInText_ScrubsEmbeddedURLKeepsContext(t *testing.T) {
	wrapped := fmt.Errorf("send request: %w", &urlErr{
		url: "https://user:s3cret@collector.example.com/v1/traces?api_key=abc123",
	})
	got := RedactURLsInText(wrapped.Error())

	for _, leak := range []string{"s3cret", "api_key", "abc123", "user:"} {
		if strings.Contains(got, leak) {
			t.Errorf("RedactURLsInText leaked %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "https://collector.example.com") {
		t.Errorf("RedactURLsInText dropped the safe host: %s", got)
	}
	if !strings.Contains(got, "send request") || !strings.Contains(got, "dial refused") {
		t.Errorf("RedactURLsInText dropped surrounding error context: %s", got)
	}
}

func TestRedactURLsInText_NoURLIsUnchanged(t *testing.T) {
	in := "context deadline exceeded"
	if got := RedactURLsInText(in); got != in {
		t.Errorf("RedactURLsInText(%q) = %q, want unchanged", in, got)
	}
}

type urlErr struct {
	url string
}

func (e *urlErr) Error() string {
	return fmt.Sprintf("Post %q: dial refused", e.url)
}
