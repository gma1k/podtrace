package v1alpha1

import (
	"strings"
	"testing"
)

func TestParseSchedule(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"standard 5-field", "*/5 * * * *", false},
		{"with seconds (6-field)", "0 */5 * * * *", false},
		{"descriptor", "@hourly", false},
		{"empty", "", true},
		{"garbage", "not a cron", true},
		{"too many fields", "* * * * * * * *", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sched, err := ParseSchedule(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSchedule(%q) err = %v, wantErr %v", tt.expr, err, tt.wantErr)
			}
			if !tt.wantErr && sched == nil {
				t.Errorf("expected non-nil schedule for %q", tt.expr)
			}
		})
	}
}

func TestValidateObjectStoreReference(t *testing.T) {
	tests := []struct {
		name    string
		ref     *ObjectStoreReference
		wantErr string
	}{
		{"nil ref is ok", nil, ""},
		{"empty URI", &ObjectStoreReference{URI: ""}, "is required"},
		{"valid s3", &ObjectStoreReference{URI: "s3://bucket/key"}, ""},
		{"valid gs", &ObjectStoreReference{URI: "gs://bucket/key"}, ""},
		{"valid azblob", &ObjectStoreReference{URI: "azblob://account/container/key"}, ""},
		{"bad scheme", &ObjectStoreReference{URI: "ftp://host/path"}, "unsupported URI scheme"},
		{"missing host", &ObjectStoreReference{URI: "s3:///key"}, "must include scheme and host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateObjectStoreReference(tt.ref)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateObjectStoreURI_Variants(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr string
	}{
		{"s3 ok", "s3://bucket/prefix/", ""},
		{"gs ok", "gs://bucket/object", ""},
		{"azblob with container", "azblob://account/container/blob", ""},
		{"azblob without container", "azblob://account", "must include a container"},
		{"azblob empty path", "azblob://account/", "must include a container"},
		{"empty scheme", "//host/path", "must include scheme and host"},
		{"unsupported", "http://example.com/x", "unsupported URI scheme"},
		{"unparseable", "://", "missing protocol scheme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateObjectStoreURI(tt.uri)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error for %q, got %v", tt.uri, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateObjectStoreURI(%q) = %v, want substring %q", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestValidateExporterConfigVariant(t *testing.T) {
	tests := []struct {
		name    string
		spec    ExporterConfigSpec
		wantErr string
	}{
		{
			name:    "otlp populated and matching",
			spec:    ExporterConfigSpec{Type: ExporterTypeOTLP, OTLP: &OTLPExporter{}},
			wantErr: "",
		},
		{
			name:    "jaeger populated and matching",
			spec:    ExporterConfigSpec{Type: ExporterTypeJaeger, Jaeger: &JaegerExporter{}},
			wantErr: "",
		},
		{
			name:    "none populated",
			spec:    ExporterConfigSpec{Type: ExporterTypeOTLP},
			wantErr: "must be set",
		},
		{
			name:    "two populated",
			spec:    ExporterConfigSpec{Type: ExporterTypeOTLP, OTLP: &OTLPExporter{}, Zipkin: &ZipkinExporter{}},
			wantErr: "only one of",
		},
		{
			name:    "type mismatch",
			spec:    ExporterConfigSpec{Type: ExporterTypeSplunk, DataDog: &DataDogExporter{}},
			wantErr: "does not match populated field",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExporterConfigVariant(tt.spec)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateExporterConfigVariant = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
