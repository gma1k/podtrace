package operator

import "testing"

func TestBundleViewFromData_NilOnError(t *testing.T) {
	if got := bundleViewFromData(nil); got != nil {
		t.Errorf("expected nil payload on error, got %+v", got)
	}

	if got := bundleViewFromData(map[string]string{"version": "v999"}); got != nil {
		t.Errorf("expected nil payload for unsupported version, got %+v", got)
	}
}

func TestBundleViewFromData_ValidData(t *testing.T) {
	got := bundleViewFromData(map[string]string{
		"type":     "otlp",
		"endpoint": "otel:4318",
	})
	if got == nil {
		t.Fatal("expected non-nil payload for valid data")
	}
	if string(got.Type) != "otlp" {
		t.Errorf("Type = %q, want otlp", got.Type)
	}
	if got.Endpoint != "otel:4318" {
		t.Errorf("Endpoint = %q, want otel:4318", got.Endpoint)
	}
}
