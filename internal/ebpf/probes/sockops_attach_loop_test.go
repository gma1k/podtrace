package probes

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/config"
)

type stubLink struct{ link.Link }

func withSockOpsOn(t *testing.T) {
	t.Helper()
	restore := config.SockOpsRTTEnabled
	config.SockOpsRTTEnabled = true
	t.Cleanup(func() { config.SockOpsRTTEnabled = restore })
}

func withAttach(t *testing.T, fn func(link.CgroupOptions) (link.Link, error)) {
	t.Helper()
	orig := attachCgroupLink
	attachCgroupLink = fn
	t.Cleanup(func() { attachCgroupLink = orig })
}

func sockOpsCollection(withStampers bool) *ebpf.Collection {
	progs := map[string]*ebpf.Program{"sockops_rtt": {}}
	if withStampers {
		progs["cgroup_skb_stamp_egress"] = &ebpf.Program{}
		progs["cgroup_skb_stamp_ingress"] = &ebpf.Program{}
	}
	return &ebpf.Collection{Programs: progs}
}

func TestEveryCgroupGetsTheObserverAndBothStampers(t *testing.T) {
	withSockOpsOn(t)
	var attached []ebpf.AttachType
	withAttach(t, func(o link.CgroupOptions) (link.Link, error) {
		attached = append(attached, o.Attach)
		return stubLink{}, nil
	})

	links := AttachSockOpsProbes(sockOpsCollection(true), []string{"/cg/a", "/cg/b"})
	if len(links) != 6 {
		t.Fatalf("got %d links for two cgroups, want 6: the sock_ops observer can only "+
			"attribute a sample the cgroup_skb stampers have tagged, so all three go on each", len(links))
	}
	counts := map[ebpf.AttachType]int{}
	for _, a := range attached {
		counts[a]++
	}
	for _, typ := range []ebpf.AttachType{ebpf.AttachCGroupSockOps, ebpf.AttachCGroupInetEgress, ebpf.AttachCGroupInetIngress} {
		if counts[typ] != 2 {
			t.Errorf("attach type %v used %d times, want once per cgroup", typ, counts[typ])
		}
	}
}

func TestAFailedAttachIsSkippedAndTheRestStillAttach(t *testing.T) {
	withSockOpsOn(t)
	withAttach(t, func(o link.CgroupOptions) (link.Link, error) {
		if o.Path == "/cg/broken" {
			return nil, errors.New("cgroup v1")
		}
		return stubLink{}, nil
	})

	links := AttachSockOpsProbes(sockOpsCollection(false), []string{"/cg/broken", "/cg/good"})
	if len(links) != 1 {
		t.Errorf("got %d links, want 1: the good cgroup's observer, the broken one skipped", len(links))
	}
}

func TestAttachingToNothingReturnsNoLinks(t *testing.T) {
	withSockOpsOn(t)
	withAttach(t, func(link.CgroupOptions) (link.Link, error) { return nil, errors.New("no cgroup v2") })

	if links := AttachSockOpsProbes(sockOpsCollection(true), []string{"/cg/a"}); len(links) != 0 {
		t.Errorf("got %d links when every attach failed", len(links))
	}
}
