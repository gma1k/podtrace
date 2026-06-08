package context

import (
	"encoding/hex"
	"testing"
)

func TestGenerateTraceID_FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		id := generateTraceID()
		if len(id) != 32 {
			t.Fatalf("trace ID length = %d, want 32 (%q)", len(id), id)
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("trace ID is not valid hex: %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate trace ID generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestGenerateSpanID_FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		id := generateSpanID()
		if len(id) != 16 {
			t.Fatalf("span ID length = %d, want 16 (%q)", len(id), id)
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("span ID is not valid hex: %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate span ID generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}
