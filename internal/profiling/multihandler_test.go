package profiling

import (
	"testing"
	"time"
)

func TestNewMultiHandler_DedupsAndSkipsEmpty(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.1", "", "10.0.0.2"}, []int{6060})
	if got := m.Len(); got != 2 {
		t.Fatalf("expected 2 distinct pod profilers, got %d", got)
	}
}

func TestMultiHandler_GenerateSection_PerPod(t *testing.T) {
	single := NewHandler("10.0.0.1", []int{6060}).GenerateSection(nil, time.Second)
	multi := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2"}, []int{6060}).
		GenerateSection(nil, time.Second)

	if len(multi) <= len(single) {
		t.Fatalf("multi-pod section (%d bytes) should exceed a single-pod section (%d bytes)", len(multi), len(single))
	}
}

func TestMultiHandler_GenerateSection_EmptyIsSafe(t *testing.T) {
	m := NewMultiHandler(nil, []int{6060})
	if m.Len() != 0 {
		t.Fatalf("expected 0 profilers, got %d", m.Len())
	}
	if out := m.GenerateSection(nil, time.Second); out != "" {
		t.Errorf("expected empty section, got %q", out)
	}
}
