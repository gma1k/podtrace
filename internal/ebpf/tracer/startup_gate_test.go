package tracer

import (
	"sort"
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

type countingLink struct {
	link.Link
	closed *int
}

func (c *countingLink) Close() error { *c.closed++; return nil }

func newCountingLink(closed *int) link.Link { return &countingLink{closed: closed} }

func groupsOf(m map[probes.ProbeGroup][]link.Link) []string {
	out := make([]string, 0, len(m))
	for g := range m {
		out = append(out, string(g))
	}
	sort.Strings(out)
	return out
}

func fixtureGroups(closed *int) map[probes.ProbeGroup][]link.Link {
	return map[probes.ProbeGroup][]link.Link{
		probes.GroupNetwork:    {newCountingLink(closed), newCountingLink(closed)},
		probes.GroupFileSystem: {newCountingLink(closed)},
		probes.GroupCPU:        {newCountingLink(closed)},
		probes.GroupMemory:     {newCountingLink(closed)},
		probes.GroupCrypto:     {newCountingLink(closed)},
		probes.GroupUSDT:       {newCountingLink(closed)},
		probes.GroupFastCGI:    {newCountingLink(closed)},
		probes.GroupTLS:        {newCountingLink(closed)},
	}
}

func TestStartupGateKeepsOnlyWantedGroups(t *testing.T) {
	closed := 0
	groups := fixtureGroups(&closed)

	disabled := gateInitialProbeGroups(groups, []string{"dns", "net", "cpu"})

	kept := groupsOf(groups)
	for _, want := range []string{"network", "cpu", "tls", "fastcgi"} {
		var found bool
		for _, g := range kept {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("group %q was closed but a wanted category needs it; kept=%v", want, kept)
		}
	}

	for _, gone := range []string{"filesystem", "memory", "crypto", "usdt"} {
		if _, still := groups[probes.ProbeGroup(gone)]; still {
			t.Errorf("group %q survived although no wanted category needs it", gone)
		}
		if _, marked := disabled[probes.ProbeGroup(gone)]; !marked {
			t.Errorf("group %q was closed but not reported as disabled, so "+
				"SetEnabledCategories could never re-attach it", gone)
		}
	}

	if closed == 0 {
		t.Error("no links were closed; the gate must actually detach, not just forget")
	}
}

func TestStartupGateWithEmptySetClosesEveryGateableGroup(t *testing.T) {
	closed := 0
	groups := fixtureGroups(&closed)
	total := 0
	for _, ls := range groups {
		total += len(ls)
	}

	disabled := gateInitialProbeGroups(groups, []string{})

	if len(groups) != 0 {
		t.Errorf("groups survived an empty category set: %v", groupsOf(groups))
	}
	if closed != total {
		t.Errorf("closed %d of %d links", closed, total)
	}
	if len(disabled) == 0 {
		t.Error("nothing reported as disabled, so no group could ever be re-attached")
	}
}

func TestStartupGateReportsEveryDisabledGroupForLaterReEnable(t *testing.T) {
	closed := 0
	groups := fixtureGroups(&closed)

	disabled := gateInitialProbeGroups(groups, []string{"net"})

	// Every group the gate removed must be reported, because
	// SetEnabledCategories only re-attaches groups it finds in
	// intentionallyDisabled. A group closed but unreported is gone for the
	// lifetime of the agent, and a PodTrace asking for it would silently
	// collect nothing.
	for g := range disabled {
		if _, still := groups[g]; still {
			t.Errorf("group %q reported disabled but still present", g)
		}
	}
	for g := range groupCategoryNeeds {
		_, present := groups[g]
		_, reported := disabled[g]
		if !present && !reported {
			t.Errorf("group %q is neither attached nor reported as disabled", g)
		}
		if present && reported {
			t.Errorf("group %q is both attached and reported as disabled", g)
		}
	}
}

func TestStartupGateLeavesUngateableGroupsAlone(t *testing.T) {
	closed := 0
	groups := fixtureGroups(&closed)
	groups[probes.GroupDatabase] = []link.Link{newCountingLink(&closed)}
	groups[probes.GroupPool] = []link.Link{newCountingLink(&closed)}

	gateInitialProbeGroups(groups, []string{})

	for _, ungateable := range []probes.ProbeGroup{probes.GroupDatabase, probes.GroupPool} {
		if _, ok := groups[ungateable]; !ok {
			t.Errorf("group %q is absent from groupCategoryNeeds, so the gate must "+
				"not touch it; its lifecycle belongs to the container uprobe path", ungateable)
		}
	}
}

func TestWithInitialCategoriesNormalisesNil(t *testing.T) {
	var o tracerOptions
	WithInitialCategories(nil)(&o)

	if !o.gateAtStartup {
		t.Error("passing the option must enable gating even with a nil slice")
	}
	if o.initialCategories == nil {
		t.Error("nil must become an empty slice; a nil set reaching " +
			"SetEnabledCategories means \"do not gate\", which is the opposite of " +
			"what an explicit empty request asks for")
	}
	if len(o.initialCategories) != 0 {
		t.Errorf("got %v, want empty", o.initialCategories)
	}
}

func TestNoOptionMeansNoGating(t *testing.T) {
	var o tracerOptions
	if o.gateAtStartup {
		t.Error("the zero value must leave every group attached, so the CLI keeps " +
			"collecting everything without asking")
	}
}
