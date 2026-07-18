package exporter

import (
	"strings"
	"testing"
)

func TestValidateExporterEndpoint(t *testing.T) {
	const def = "http://localhost:8126/v0.4/traces"
	cases := []struct {
		name     string
		endpoint string
		wantErr  string
	}{
		{"empty-uses-loopback-default", "", ""},
		{"https-allowed", "https://intake.example.com/api", ""},
		{"http-loopback-allowed", "http://127.0.0.1:8126/x", ""},
		{"http-localhost-allowed", "http://localhost:8088/services/collector", ""},
		{"bare-hostport-defaults-http-loopback", "localhost:8126", ""},
		{"http-nonloopback-refused", "http://intake.datadoghq.com/api", "cleartext http"},
		{"http-internal-ip-refused", "http://10.0.0.5:8126/x", "cleartext http"},
		{"file-scheme-rewritten-then-refused", "file:///etc/shadow", "cleartext http"}, // becomes http://file/... (host "file", not a file read) → refused as cleartext non-loopback
		{"gopher-scheme-refused", "gopher://evil.internal:70/x", "scheme must be http or https"},
		{"ftp-scheme-refused", "ftp://evil.internal/x", "scheme must be http or https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateExporterEndpoint(tc.endpoint, def)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got == "" {
					t.Fatal("expected a normalized endpoint, got empty")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (normalized=%q)", tc.wantErr, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestExporterConstructorsRejectCleartextCredentials(t *testing.T) {
	if _, err := NewDataDogExporter("http://intake.datadoghq.com/api", "secret-key", 1.0); err == nil {
		t.Error("DataDog: expected rejection of cleartext non-loopback endpoint")
	}
	if _, err := NewSplunkExporter("http://splunk.example.com:8088", "hec-token", 1.0); err == nil {
		t.Error("Splunk: expected rejection of cleartext non-loopback endpoint")
	}
	if _, err := NewZipkinExporter("gopher://evil.internal/x", 1.0); err == nil {
		t.Error("Zipkin: expected rejection of non-http scheme")
	}
	if _, err := NewDataDogExporter("", "secret-key", 1.0); err != nil {
		t.Errorf("DataDog with default loopback endpoint should construct: %v", err)
	}
	if _, err := NewSplunkExporter("https://splunk.example.com:8088", "hec-token", 1.0); err != nil {
		t.Errorf("Splunk with https should construct: %v", err)
	}
}
