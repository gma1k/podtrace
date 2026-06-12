package objectstore

import (
	"net/url"
	"strings"
	"testing"
)

// TestRedactURL_StripsCredentialQueries: retry log lines carried the full
// request URL — Azure SAS tokens and S3 presigned credentials live in the
// query string and were written to stderr on every retried attempt.
func TestRedactURL_StripsCredentialQueries(t *testing.T) {
	u, err := url.Parse("https://acct.blob.core.windows.net/c/report.json?sv=2024&sig=SECRETSIG&se=2026")
	if err != nil {
		t.Fatal(err)
	}
	got := redactURL(u)
	if strings.Contains(got, "SECRETSIG") || strings.Contains(got, "sig=") {
		t.Errorf("redactURL leaked the SAS signature: %q", got)
	}
	if !strings.Contains(got, "acct.blob.core.windows.net/c/report.json") {
		t.Errorf("redactURL lost host/path context: %q", got)
	}

	if got := redactURL(nil); got != "" {
		t.Errorf("redactURL(nil) = %q, want empty", got)
	}

	plain, _ := url.Parse("https://storage.googleapis.com/bucket/obj")
	if got := redactURL(plain); got != "https://storage.googleapis.com/bucket/obj" {
		t.Errorf("query-less URL must pass through unchanged, got %q", got)
	}
}
