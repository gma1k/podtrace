package nodespawn

import "testing"

func TestNodePodLabel(t *testing.T) {
	if got := nodePodLabel(nil); got != "" {
		t.Errorf("empty = %q, want \"\"", got)
	}
	if got := nodePodLabel([]PodRef{{Name: "cart-abc"}}); got != "cart-abc" {
		t.Errorf("single = %q, want cart-abc", got)
	}
	// distinct names joined; duplicates collapsed.
	if got := nodePodLabel([]PodRef{{Name: "a"}, {Name: "b"}, {Name: "a"}}); got != "a,b" {
		t.Errorf("multi = %q, want a,b", got)
	}
}
