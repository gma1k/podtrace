package metricsexporter

import (
	"fmt"
	"testing"
)

// TestLabelCardinalityLimiter is a regression test for unbounded label
// cardinality: traffic-derived labels (commands, methods, topics) and
// pod-churn labels used to mint one Prometheus series per distinct observed
// value forever.
func TestLabelCardinalityLimiter(t *testing.T) {
	l := newLabelCardinalityLimiter(3)

	for _, v := range []string{"a", "b", "c"} {
		if got := l.bound(v); got != v {
			t.Errorf("bound(%q) = %q, want passthrough under the cap", v, got)
		}
	}
	if got := l.bound("b"); got != "b" {
		t.Errorf("bound(b) = %q, want b (already admitted)", got)
	}
	for i := 0; i < 100; i++ {
		if got := l.bound(fmt.Sprintf("new-%d", i)); got != "other" {
			t.Fatalf("bound(new-%d) = %q, want \"other\" beyond the cap", i, got)
		}
	}
	if got := l.bound(""); got != "" {
		t.Errorf("bound(\"\") = %q, want empty", got)
	}
}