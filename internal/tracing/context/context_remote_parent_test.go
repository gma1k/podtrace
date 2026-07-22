package context

import "testing"

func TestTraceContext_HasRemoteParent(t *testing.T) {
	cases := []struct {
		name    string
		traceID string
		parent  string
		want    bool
	}{
		{"both set", "abc", "def", true},
		{"no parent", "abc", "", false},
		{"no trace id", "", "def", false},
		{"neither", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := &TraceContext{TraceID: c.traceID, ParentSpanID: c.parent}
			if got := tc.HasRemoteParent(); got != c.want {
				t.Errorf("HasRemoteParent()=%v want %v", got, c.want)
			}
		})
	}
}

func TestIsLowerHex_Cases(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"00ff", true},
		{"0123456789abcdef", true},
		{"ABCD", false},
		{"gg", false},
		{"12 34", false},
	}
	for _, c := range cases {
		if got := isLowerHex(c.in); got != c.want {
			t.Errorf("isLowerHex(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestParseW3CTraceParent_AllZeroRejected(t *testing.T) {
	zeroTrace := "00-00000000000000000000000000000000-0000000000000001-01"
	if _, err := ParseW3CTraceParent(zeroTrace); err == nil {
		t.Error("expected all-zero trace ID to be rejected")
	}

	zeroParent := "00-0000000000000000000000000000abcd-0000000000000000-01"
	if _, err := ParseW3CTraceParent(zeroParent); err == nil {
		t.Error("expected all-zero parent ID to be rejected")
	}
}
