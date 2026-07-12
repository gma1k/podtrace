package context

import "testing"

func TestParseW3CTraceParent_Rejects(t *testing.T) {
	cases := []struct {
		name        string
		traceParent string
	}{
		{"non-hex trace id", "00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		{"uppercase trace id", "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"},
		{"non-hex parent id", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902zz-01"},
		{"all-zero trace id", "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
		{"all-zero parent id", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"},
		{"reserved version ff", "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseW3CTraceParent(tc.traceParent); err == nil {
				t.Fatalf("ParseW3CTraceParent(%q) = %+v, want error", tc.traceParent, got)
			}
		})
	}
}

func TestParseW3CTraceParent_AcceptsValid(t *testing.T) {
	tc, err := ParseW3CTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if err != nil {
		t.Fatalf("valid traceparent rejected: %v", err)
	}
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || tc.ParentSpanID != "00f067aa0ba902b7" || tc.Flags != 0x01 {
		t.Fatalf("parsed context = %+v, unexpected fields", tc)
	}
}

func TestNewTraceContextFromSeed_Deterministic(t *testing.T) {
	a := NewTraceContextFromSeed("req-123")
	b := NewTraceContextFromSeed("req-123")
	c := NewTraceContextFromSeed("req-999")

	if a.TraceID != b.TraceID {
		t.Fatalf("same seed produced different trace IDs: %s vs %s", a.TraceID, b.TraceID)
	}
	if a.TraceID == c.TraceID {
		t.Fatalf("distinct seeds collided on trace ID %s", a.TraceID)
	}
	if len(a.TraceID) != 32 || !isLowerHex(a.TraceID) {
		t.Fatalf("derived trace ID %q is not a 32-char lowercase hex string", a.TraceID)
	}
	if a.SpanID == b.SpanID {
		t.Fatalf("span IDs must be unique per event, got %s twice", a.SpanID)
	}
	if !a.IsValid() {
		t.Fatal("derived context must be valid")
	}
}
