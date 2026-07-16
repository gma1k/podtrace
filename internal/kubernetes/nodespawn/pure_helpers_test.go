package nodespawn

import "testing"

func TestPodRef_PreResolved(t *testing.T) {
	r := PodRef{
		Namespace:     "ns1",
		Name:          "cart-abc",
		ContainerID:   "deadbeef",
		ContainerName: "app",
	}
	if got := r.PreResolved(); len(got) != 1 || got[0] != "ns1/cart-abc/deadbeef/app" {
		t.Errorf("PreResolved() = %v, want [ns1/cart-abc/deadbeef/app] (legacy singular fields)", got)
	}

	r2 := PodRef{Namespace: "ns", Name: "p"}
	if got := r2.PreResolved(); len(got) != 0 {
		t.Errorf("PreResolved() with no containers = %v, want empty", got)
	}

	multi := PodRef{
		Namespace: "ns1", Name: "cart-abc",
		Containers: []ContainerRef{{ID: "aaa", Name: "app"}, {ID: "bbb", Name: "sidecar"}},
	}
	got := multi.PreResolved()
	if len(got) != 2 || got[0] != "ns1/cart-abc/aaa/app" || got[1] != "ns1/cart-abc/bbb/sidecar" {
		t.Errorf("PreResolved() multi-container = %v, want one ref per container", got)
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
