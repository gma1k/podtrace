package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/podtrace/podtrace/internal/ebpf/probes"
)

func TestPidForContainer_NoCgroupMatchReturnsZero(t *testing.T) {
	tr := &Tracer{
		containerPID: 42,
		cgroupPaths:  []string{"/sys/fs/cgroup/kubepods/poduid/othercontainerid"},
	}
	if pids := tr.pidsForContainer("deadbeefdeadbeef", nil); len(pids) != 1 || pids[0] != 0 {
		t.Fatalf("pidsForContainer = %v, want [0] (must not borrow another container's PID)", pids)
	}
}

func TestPidsForContainer_SeedsUsedWhenCgroupUnreadable(t *testing.T) {
	tr := &Tracer{}
	if pids := tr.pidsForContainer("deadbeefdeadbeef", []uint32{7, 0, 3, 7}); len(pids) != 2 || pids[0] != 3 || pids[1] != 7 {
		t.Fatalf("pidsForContainer with seeds = %v, want [3 7]", pids)
	}
}

func TestDisableProbeGroup_ClosesContainerUprobeLinks(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
	tlsA, tlsB, dbA := &fakeLink{}, &fakeLink{}, &fakeLink{}
	tr.containerUprobes = map[string]*containerUprobeSet{
		"containeraaaa": {pids: []uint32{1}, links: map[probes.ProbeGroup][]link.Link{
			probes.GroupTLS:      {tlsA},
			probes.GroupDatabase: {dbA},
		}},
		"containerbbbb": {pids: []uint32{2}, links: map[probes.ProbeGroup][]link.Link{
			probes.GroupTLS: {tlsB},
		}},
	}

	if err := tr.DisableProbeGroup(probes.GroupTLS); err != nil {
		t.Fatalf("DisableProbeGroup: %v", err)
	}

	if tlsA.closes.Load() != 1 || tlsB.closes.Load() != 1 {
		t.Errorf("TLS container link closes = %d/%d, want 1/1",
			tlsA.closes.Load(), tlsB.closes.Load())
	}
	if dbA.closes.Load() != 0 {
		t.Errorf("Database link closes = %d, want 0 (other groups must stay attached)", dbA.closes.Load())
	}
	for id, set := range tr.containerUprobes {
		if len(set.links[probes.GroupTLS]) != 0 {
			t.Errorf("container %q still holds TLS links after disable", id)
		}
	}
}

func TestEnableProbeGroup_ReattachesContainerUprobes(t *testing.T) {
	attachCalls := map[string]int{}
	tr := &Tracer{
		probeGroups: map[probes.ProbeGroup][]link.Link{},
		collection:  &ebpf.Collection{},
	}
	tr.attachContainerGroupFn = func(g probes.ProbeGroup, id string, pids []uint32) []link.Link {
		attachCalls[string(g)+"/"+id]++
		return []link.Link{&fakeLink{}}
	}
	tr.containerUprobes = map[string]*containerUprobeSet{
		"containeraaaa": {pids: []uint32{1}, links: map[probes.ProbeGroup][]link.Link{
			probes.GroupTLS: {&fakeLink{}},
		}},
		"containerbbbb": {pids: []uint32{2}, links: map[probes.ProbeGroup][]link.Link{
			probes.GroupTLS: {&fakeLink{}},
		}},
	}

	if err := tr.DisableProbeGroup(probes.GroupTLS); err != nil {
		t.Fatalf("DisableProbeGroup: %v", err)
	}
	if err := tr.EnableProbeGroup(probes.GroupTLS); err != nil {
		t.Fatalf("EnableProbeGroup: %v", err)
	}

	for _, id := range []string{"containeraaaa", "containerbbbb"} {
		if got := attachCalls["tls/"+id]; got != 1 {
			t.Errorf("TLS attach calls for %q = %d, want 1", id, got)
		}
		if len(tr.containerUprobes[id].links[probes.GroupTLS]) != 1 {
			t.Errorf("container %q has no TLS links after enable", id)
		}
	}
}

func TestSetContainerTargets_SkipsIntentionallyDisabledGroups(t *testing.T) {
	requested := map[probes.ProbeGroup]int{}
	tr := &Tracer{
		probeGroups:           map[probes.ProbeGroup][]link.Link{},
		intentionallyDisabled: map[probes.ProbeGroup]struct{}{probes.GroupTLS: {}},
	}
	tr.attachContainerGroupFn = func(g probes.ProbeGroup, id string, pids []uint32) []link.Link {
		requested[g]++
		return []link.Link{&fakeLink{}}
	}

	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{1}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}

	if requested[probes.GroupTLS] != 0 {
		t.Errorf("GroupTLS attach requested %d times, want 0 (group is disabled)", requested[probes.GroupTLS])
	}
	for _, g := range []probes.ProbeGroup{probes.GroupDatabase, probes.GroupPool, probes.GroupCache, probes.GroupMessaging} {
		if requested[g] != 1 {
			t.Errorf("group %q attach requested %d times, want 1", g, requested[g])
		}
	}
}

// TestSetEnabledCategories_DisablesContainerOnlyGroups: GroupTLS has no
// group-level kprobes, its links live only in containerUprobes.
func TestSetEnabledCategories_DisablesContainerOnlyGroups(t *testing.T) {
	tr := &Tracer{
		probeGroups:           map[probes.ProbeGroup][]link.Link{},
		intentionallyDisabled: map[probes.ProbeGroup]struct{}{},
	}
	tlsLink := &fakeLink{}
	tr.containerUprobes = map[string]*containerUprobeSet{
		"containeraaaa": {pids: []uint32{1}, links: map[probes.ProbeGroup][]link.Link{
			probes.GroupTLS: {tlsLink},
		}},
	}

	if err := tr.SetEnabledCategories([]string{"fs"}); err != nil {
		t.Fatalf("SetEnabledCategories: %v", err)
	}

	if tlsLink.closes.Load() != 1 {
		t.Errorf("container TLS link closes = %d, want 1 (fs-only categories must detach TLS)", tlsLink.closes.Load())
	}
	if _, ok := tr.intentionallyDisabled[probes.GroupTLS]; !ok {
		t.Error("GroupTLS not recorded in intentionallyDisabled (re-enable would never fire)")
	}
}

// TestSetEnabledCategories_GatesGroupsBeforeAttach: category gating runs at
// policy load, BEFORE container targets exist.
func TestSetEnabledCategories_GatesGroupsBeforeAttach(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
	if err := tr.SetEnabledCategories([]string{"fs"}); err != nil {
		t.Fatalf("SetEnabledCategories: %v", err)
	}

	requested := map[probes.ProbeGroup]int{}
	tr.attachContainerGroupFn = func(g probes.ProbeGroup, id string, pids []uint32) []link.Link {
		requested[g]++
		return []link.Link{&fakeLink{}}
	}
	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{1}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}

	if requested[probes.GroupTLS] != 0 {
		t.Errorf("GroupTLS attach requested %d times, want 0 (gated before any target attached)", requested[probes.GroupTLS])
	}
	if requested[probes.GroupDatabase] != 1 {
		t.Errorf("GroupDatabase attach requested %d times, want 1 (not category-gateable)", requested[probes.GroupDatabase])
	}
}

func TestClassifyCgroupCapacity(t *testing.T) {
	cases := []struct {
		name       string
		count      int
		maxEntries uint32
		want       int
	}{
		{"empty", 0, 4096, cgroupCapacityOK},
		{"at 80 percent", 3276, 4096, cgroupCapacityOK},
		{"just above 80 percent", 3277, 4096, cgroupCapacityNearFull},
		{"exactly full", 4096, 4096, cgroupCapacityNearFull},
		{"over capacity", 4097, 4096, cgroupCapacityExceeded},
		{"unknown max entries", 10000, 0, cgroupCapacityOK},
	}
	for _, c := range cases {
		if got := classifyCgroupCapacity(c.count, c.maxEntries); got != c.want {
			t.Errorf("%s: classifyCgroupCapacity(%d, %d) = %d, want %d",
				c.name, c.count, c.maxEntries, got, c.want)
		}
	}
}

func TestWarnOnCgroupCapacity_LogsOncePerCount(t *testing.T) {
	tr := &Tracer{}

	tr.warnOnCgroupCapacity(4000, 4096)
	if got := tr.cgroupCapacityWarned.Load(); got != 4000 {
		t.Fatalf("cgroupCapacityWarned = %d, want 4000", got)
	}
	tr.warnOnCgroupCapacity(4000, 4096)
	if got := tr.cgroupCapacityWarned.Load(); got != 4000 {
		t.Fatalf("cgroupCapacityWarned after repeat = %d, want 4000", got)
	}
	tr.warnOnCgroupCapacity(100, 4096)
	if got := tr.cgroupCapacityWarned.Load(); got != 0 {
		t.Fatalf("cgroupCapacityWarned after recovery = %d, want 0 (re-armed)", got)
	}
}
