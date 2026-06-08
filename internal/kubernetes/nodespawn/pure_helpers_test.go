package nodespawn

import "testing"

func TestPodRef_PreResolved(t *testing.T) {
	r := PodRef{
		Namespace:     "ns1",
		Name:          "cart-abc",
		ContainerID:   "deadbeef",
		ContainerName: "app",
	}
	want := "ns1/cart-abc/deadbeef/app"
	if got := r.PreResolved(); got != want {
		t.Errorf("PreResolved() = %q, want %q", got, want)
	}

	r2 := PodRef{Namespace: "ns", Name: "p"}
	if got, want := r2.PreResolved(), "ns/p//"; got != want {
		t.Errorf("PreResolved() = %q, want %q", got, want)
	}
}

func TestNodeTargets_Empty(t *testing.T) {
	var empty NodeTargets
	if !empty.Empty() {
		t.Errorf("zero-value NodeTargets should be Empty()")
	}

	if (NodeTargets{NodeNames: []string{}}).Empty() != true {
		t.Errorf("NodeTargets with empty NodeNames should be Empty()")
	}

	nonEmpty := NodeTargets{NodeNames: []string{"node-1"}}
	if nonEmpty.Empty() {
		t.Errorf("NodeTargets with a node should not be Empty()")
	}
}

func TestHostname(t *testing.T) {
	if got := Hostname(); got == "" {
		t.Errorf("Hostname() returned empty string")
	}
}
