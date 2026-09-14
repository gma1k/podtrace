package nodespawn

import (
	"strings"
	"testing"
)

func TestPreResolvedCarriesThePodIP(t *testing.T) {
	r := PodRef{
		Namespace:   "shop",
		Name:        "checkout-1",
		PodIP:       "10.244.2.7",
		ContainerID: "abc123",
		Containers:  []ContainerRef{{ID: "abc123", Name: "app"}},
	}

	got := r.PreResolved()
	if len(got) != 1 {
		t.Fatalf("got %d refs, want 1", len(got))
	}
	if got[0] != "shop/checkout-1/abc123/app/10.244.2.7" {
		t.Errorf("ref = %q, want the pod IP appended.\n\nThe spawned pod cannot look the "+
			"IP up again -- it has no API access -- so without it --profiling finds no "+
			"target, skips pprof discovery, and the whole profiling path is inert.", got[0])
	}
}

func TestPreResolvedOmitsAnAbsentPodIP(t *testing.T) {
	r := PodRef{
		Namespace:   "shop",
		Name:        "checkout-1",
		ContainerID: "abc123",
		Containers:  []ContainerRef{{ID: "abc123", Name: "app"}},
	}

	got := r.PreResolved()
	if got[0] != "shop/checkout-1/abc123/app" {
		t.Errorf("ref = %q, want no trailing separator when there is no IP", got[0])
	}
	if strings.HasSuffix(got[0], "/") {
		t.Error("a trailing separator would parse as an empty container name on an " +
			"older binary")
	}
}

func TestEveryContainerOfAPodCarriesTheSameIP(t *testing.T) {
	r := PodRef{
		Namespace: "shop",
		Name:      "checkout-1",
		PodIP:     "10.244.2.7",
		Containers: []ContainerRef{
			{ID: "aaa", Name: "app"},
			{ID: "bbb", Name: "sidecar"},
		},
	}

	got := r.PreResolved()
	if len(got) != 2 {
		t.Fatalf("got %d refs, want 2", len(got))
	}
	for _, ref := range got {
		if !strings.HasSuffix(ref, "/10.244.2.7") {
			t.Errorf("ref %q lost the pod IP; containers of one pod share it", ref)
		}
	}
}
