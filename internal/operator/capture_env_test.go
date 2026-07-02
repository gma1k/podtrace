package operator

import (
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestCaptureEnv_NilAndEmpty(t *testing.T) {
	if env := captureEnv(nil); env != nil {
		t.Errorf("nil spec: want no env, got %v", env)
	}
	if env := captureEnv(&podtracev1alpha1.CaptureSpec{}); env != nil {
		t.Errorf("empty spec: want no env, got %v", env)
	}
}

func TestCaptureEnv_Headers(t *testing.T) {
	env := captureEnv(&podtracev1alpha1.CaptureSpec{
		Headers: []string{"content-type", "x-request-id"},
	})
	if v, ok := envValue(env, "PODTRACE_CAPTURE_HEADERS"); !ok || v != "content-type,x-request-id" {
		t.Errorf("PODTRACE_CAPTURE_HEADERS=%q ok=%v", v, ok)
	}
}
