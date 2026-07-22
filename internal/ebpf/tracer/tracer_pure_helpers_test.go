package tracer

import (
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/podtrace/podtrace/internal/ebpf/probes"
)

func TestSamePIDSet_Comparisons(t *testing.T) {
	cases := []struct {
		name string
		a, b []uint32
		want bool
	}{
		{"equal", []uint32{1, 2, 3}, []uint32{1, 2, 3}, true},
		{"length differs", []uint32{1, 2}, []uint32{1, 2, 3}, false},
		{"element differs", []uint32{1, 2, 3}, []uint32{1, 9, 3}, false},
		{"both empty", []uint32{}, []uint32{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := samePIDSet(c.a, c.b); got != c.want {
				t.Errorf("samePIDSet(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

func TestAddLinks_EmptyIsNoop(t *testing.T) {
	tr := &Tracer{}
	tr.addLinks(nil)
	tr.addLinks([]link.Link{})
	if got := tr.linkCount(); got != 0 {
		t.Errorf("linkCount after empty addLinks = %d, want 0", got)
	}
}

func TestWarnOnCgroupCapacity_ExceededRecordsCount(t *testing.T) {
	tr := &Tracer{}
	tr.warnOnCgroupCapacity(5000, 4096)
	if got := tr.cgroupCapacityWarned.Load(); got != 5000 {
		t.Errorf("cgroupCapacityWarned after exceeded = %d, want 5000", got)
	}
}

func TestIsLikelyTransientComm(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0", true},
		{"5", true},
		{"9", true},
		{"a", false},
		{":", false},
		{"/", false},
		{"12", false},
	}
	for _, c := range cases {
		if got := isLikelyTransientComm(c.in); got != c.want {
			t.Errorf("isLikelyTransientComm(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestProbeGroupNeededBy(t *testing.T) {
	cases := []struct {
		name   string
		group  probes.ProbeGroup
		wanted map[string]struct{}
		want   bool
	}{
		{"ungated group always needed", probes.GroupDatabase, map[string]struct{}{}, true},
		{"gated group with matching category", probes.GroupFileSystem, map[string]struct{}{"fs": {}}, true},
		{"gated group without matching category", probes.GroupFileSystem, map[string]struct{}{"net": {}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := probeGroupNeededBy(c.group, c.wanted); got != c.want {
				t.Errorf("probeGroupNeededBy(%q, %v) = %v, want %v", c.group, c.wanted, got, c.want)
			}
		})
	}
}

func TestEnableProbeGroup_AlreadyAttachedIsNoop(t *testing.T) {
	existing := &fakeLink{}
	tr := &Tracer{
		probeGroups: map[probes.ProbeGroup][]link.Link{
			probes.GroupTLS: {existing},
		},
	}

	if err := tr.EnableProbeGroup(probes.GroupTLS); err != nil {
		t.Fatalf("EnableProbeGroup on already-attached group: %v", err)
	}

	tr.probeGroupsMu.Lock()
	defer tr.probeGroupsMu.Unlock()
	got := tr.probeGroups[probes.GroupTLS]
	if len(got) != 1 || got[0] != existing {
		t.Errorf("EnableProbeGroup mutated an already-attached group: got %v", got)
	}
	if existing.closes.Load() != 0 {
		t.Errorf("already-attached link was closed %d times, want 0", existing.closes.Load())
	}
}
