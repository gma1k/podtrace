package objectstore

import (
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	cases := []struct {
		name       string
		uri        string
		wantScheme string
		wantBucket string
		wantPath   string
		wantPrefix bool
		wantErr    string
	}{
		{"S3-prefix-trailing-slash", "s3://my-bucket/reports/", "s3", "my-bucket", "reports", true, ""},
		{"S3-bucket-root", "s3://my-bucket/", "s3", "my-bucket", "", true, ""},
		{"S3-bucket-no-trailing-slash", "s3://my-bucket", "s3", "my-bucket", "", true, ""},
		{"S3-exact-key", "s3://my-bucket/path/report.txt", "s3", "my-bucket", "path/report.txt", false, ""},
		{"GCS-prefix", "gs://bucket/diagnose/", "gs", "bucket", "diagnose", true, ""},
		{"GCS-exact-key", "gs://bucket/diagnose/a.txt", "gs", "bucket", "diagnose/a.txt", false, ""},
		{"Azure-prefix", "azblob://acct/container/prefix/", "azblob", "container", "prefix", true, ""},
		{"Azure-exact-key", "azblob://acct/container/prefix/a.txt", "azblob", "container", "prefix/a.txt", false, ""},
		{"Azure-container-root", "azblob://acct/container/", "azblob", "container", "", true, ""},
		{"empty", "", "", "", "", false, "empty URI"},
		{"no-scheme", "bucket/key", "", "", "", false, "must include scheme"},
		{"unknown-scheme", "ftp://bucket/key", "", "", "", false, "unsupported URI scheme"},
		{"azure-missing-container", "azblob://acct/", "", "", "", false, "must include a container"},
		{"azure-empty-container-after-account", "azblob://acct", "", "", "", false, "must include a container"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseURI(tc.uri)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (parsed %+v)", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.scheme != tc.wantScheme || got.bucket != tc.wantBucket || got.path != tc.wantPath || got.prefix != tc.wantPrefix {
				t.Errorf("got {%s %s %s %v}, want {%s %s %s %v}",
					got.scheme, got.bucket, got.path, got.prefix,
					tc.wantScheme, tc.wantBucket, tc.wantPath, tc.wantPrefix)
			}
		})
	}
}

func TestResolveKey(t *testing.T) {
	cases := []struct {
		name string
		d    destination
		hint string
		want string
	}{
		{"prefix-with-path", destination{path: "reports", prefix: true}, "sess-1.txt", "reports/sess-1.txt"},
		{"prefix-empty-path", destination{path: "", prefix: true}, "sess-1.txt", "sess-1.txt"},
		{"prefix-hint-has-leading-slash", destination{path: "reports", prefix: true}, "/sess-1.txt", "reports/sess-1.txt"},
		{"exact-key-ignores-hint", destination{path: "reports/fixed.txt", prefix: false}, "ignored.txt", "reports/fixed.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.d.resolveKey(tc.hint); got != tc.want {
				t.Errorf("resolveKey(%q) on %+v = %q, want %q", tc.hint, tc.d, got, tc.want)
			}
		})
	}
}

// TestValidateURI is the contract the webhook uses. Any URI accepted
// here will be accepted by New (modulo backend client construction).
func TestValidateURI(t *testing.T) {
	good := []string{
		"s3://b/", "s3://b/p/", "s3://b/p/k.txt",
		"gs://b/", "gs://b/p/", "gs://b/k",
		"azblob://acct/container/", "azblob://acct/container/k.txt",
	}
	for _, u := range good {
		if err := ValidateURI(u); err != nil {
			t.Errorf("ValidateURI(%q) unexpected error: %v", u, err)
		}
	}
	bad := []string{
		"", "bucket/key", "ftp://b/k", "https://example.com/x",
		"azblob://acct", "azblob://acct/",
	}
	for _, u := range bad {
		if err := ValidateURI(u); err == nil {
			t.Errorf("ValidateURI(%q) should fail but returned nil", u)
		}
	}
}