package kubernetes

import "testing"

func TestParsePreResolvedRefReadsThePodIP(t *testing.T) {
	ref, err := ParsePreResolvedRef("shop/checkout-1/abc123/app/10.244.2.7")
	if err != nil {
		t.Fatalf("ParsePreResolvedRef: %v", err)
	}
	if ref.PodIP != "10.244.2.7" {
		t.Errorf("PodIP = %q, want 10.244.2.7", ref.PodIP)
	}
	if ref.ContainerName != "app" {
		t.Errorf("ContainerName = %q, want app; the IP must not be absorbed into it",
			ref.ContainerName)
	}
}

func TestAFourFieldRefFromAnOlderBinaryStillParses(t *testing.T) {
	ref, err := ParsePreResolvedRef("shop/checkout-1/abc123/app")
	if err != nil {
		t.Fatalf("ParsePreResolvedRef: %v", err)
	}
	if ref.ContainerName != "app" {
		t.Errorf("ContainerName = %q, want app", ref.ContainerName)
	}
	if ref.PodIP != "" {
		t.Errorf("PodIP = %q, want empty.\n\nA workstation binary older than the spawn "+
			"image emits four fields; inventing an IP would point pprof discovery at "+
			"nothing.", ref.PodIP)
	}
}

func TestARefWithAnEmptyContainerNameKeepsItsPodIP(t *testing.T) {
	ref, err := ParsePreResolvedRef("shop/checkout-1/abc123//10.244.2.7")
	if err != nil {
		t.Fatalf("ParsePreResolvedRef: %v", err)
	}
	if ref.ContainerName != "" || ref.PodIP != "10.244.2.7" {
		t.Errorf("got name=%q ip=%q, want an empty name and the IP intact",
			ref.ContainerName, ref.PodIP)
	}
}
