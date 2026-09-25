package tracer

import (
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

type attachRecorder struct {
	mu       sync.Mutex
	attached map[string][]*fakeLink
}

func (r *attachRecorder) attach(_ *ebpf.Collection, paths []string) []link.Link {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attached == nil {
		r.attached = map[string][]*fakeLink{}
	}
	l := &fakeLink{}
	r.attached[paths[0]] = append(r.attached[paths[0]], l)
	return []link.Link{l}
}

func (r *attachRecorder) count(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attached[path])
}

func reconcileTracer() *Tracer {
	return &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}, collection: &ebpf.Collection{}}
}

func swapAttach(t *testing.T, target *func(*ebpf.Collection, []string) []link.Link, fn func(*ebpf.Collection, []string) []link.Link) {
	t.Helper()
	orig := *target
	*target = fn
	t.Cleanup(func() { *target = orig })
}

func TestACgroupIsAttachedOnceAndDetachedWhenItLeaves(t *testing.T) {
	rec := &attachRecorder{}
	swapAttach(t, &attachDNSPacketProbes, rec.attach)
	tr := reconcileTracer()

	tr.syncDNSPacketProbes([]string{"/cg/a", "/cg/b", ""})
	tr.syncDNSPacketProbes([]string{"/cg/b"})

	if rec.count("/cg/a") != 1 || rec.count("/cg/b") != 1 {
		t.Fatalf("attach counts a=%d b=%d, want one each: a cgroup still wanted must not be "+
			"attached again, or every reconcile doubles its program", rec.count("/cg/a"), rec.count("/cg/b"))
	}
	if got := rec.attached["/cg/a"][0].closes.Load(); got != 1 {
		t.Errorf("the departed cgroup's link closed %d times, want 1", got)
	}
	if got := rec.attached["/cg/b"][0].closes.Load(); got != 0 {
		t.Errorf("the still-wanted cgroup's link was closed %d times", got)
	}
	if _, ok := tr.dnsPacketLinks[""]; ok {
		t.Error("an empty cgroup path was attached")
	}
}

func TestLinksAttachedWhileStoppingAreClosedNotKept(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var fresh *fakeLink
	swapAttach(t, &attachHTTP3Probes, func(*ebpf.Collection, []string) []link.Link {
		close(started)
		<-release
		fresh = &fakeLink{}
		return []link.Link{fresh}
	})
	tr := reconcileTracer()

	done := make(chan struct{})
	go func() { tr.syncHTTP3Probes([]string{"/cg/a"}); close(done) }()
	<-started
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	close(release)
	<-done

	if fresh.closes.Load() != 1 {
		t.Errorf("a link attached during Stop was closed %d times, want 1; it would outlive "+
			"the tracer attached to the kernel", fresh.closes.Load())
	}
	if len(tr.http3Links) != 0 {
		t.Error("a link attached during Stop was stored")
	}
}

func TestNothingIsAttachedAfterStopOrWithoutACollection(t *testing.T) {
	rec := &attachRecorder{}
	swapAttach(t, &attachDNSPacketProbes, rec.attach)

	stopped := reconcileTracer()
	if err := stopped.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	stopped.syncDNSPacketProbes([]string{"/cg/a"})

	unloaded := &Tracer{}
	unloaded.syncDNSPacketProbes([]string{"/cg/a"})

	if rec.count("/cg/a") != 0 {
		t.Errorf("attached %d times to a stopped or unloaded tracer", rec.count("/cg/a"))
	}
}

func TestSockOpsFollowsItsSwitchAndFallsBackToTheKubepodsRoot(t *testing.T) {
	rec := &attachRecorder{}
	swapAttach(t, &attachSockOpsProbes, rec.attach)
	origRoot := kubepodsRoot
	root := "/sys/fs/cgroup/kubepods.slice"
	kubepodsRoot = func() string { return root }
	t.Cleanup(func() { kubepodsRoot = origRoot })
	origEnabled := config.SockOpsRTTEnabled
	t.Cleanup(func() { config.SockOpsRTTEnabled = origEnabled })

	config.SockOpsRTTEnabled = false
	off := reconcileTracer()
	off.syncSockOpsProbes(nil)
	if rec.count(root) != 0 {
		t.Fatal("sock_ops was attached with the feature switched off")
	}

	config.SockOpsRTTEnabled = true
	on := reconcileTracer()
	on.syncSockOpsProbes(nil)
	if rec.count(root) != 1 {
		t.Errorf("attached %d times at the kubepods root, want 1: the continuous plane sets no "+
			"target cgroups, so without the fallback RTT is never measured anywhere", rec.count(root))
	}

	on.syncSockOpsProbes([]string{"/cg/target"})
	if rec.count("/cg/target") != 1 || rec.attached[root][0].closes.Load() != 1 {
		t.Error("targeted cgroups did not replace the root attachment")
	}

	root = ""
	bare := reconcileTracer()
	bare.syncSockOpsProbes(nil)
	if len(bare.sockOpsLinks) != 0 {
		t.Error("something was attached with neither targets nor a kubepods root")
	}

	if err := on.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := rec.attached["/cg/target"][0].closes.Load(); got != 1 {
		t.Errorf("Stop closed the sock_ops link %d times, want 1", got)
	}
}

func TestStopReleasesEveryKindOfLinkAndCancelsItsWork(t *testing.T) {
	dns, h3, uprobe := &fakeLink{}, &fakeLink{}, &fakeLink{}
	cancelled := false
	tr := reconcileTracer()
	tr.dnsPacketLinks = map[string][]link.Link{"/cg/a": {dns}}
	tr.http3Links = map[string][]link.Link{"/cg/a": {h3}}
	tr.containerUprobes = map[string]*containerUprobeSet{
		"c1": {pids: []uint32{1}, links: map[probes.ProbeGroup][]link.Link{probes.GroupTLS: {uprobe}}},
	}
	tr.stopCancel = func() { cancelled = true }

	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for name, l := range map[string]*fakeLink{"dns packet": dns, "http3": h3, "container uprobe": uprobe} {
		if got := l.closes.Load(); got != 1 {
			t.Errorf("the %s link closed %d times on Stop, want 1; it would stay attached "+
				"to the kernel after the agent exited", name, got)
		}
	}
	if !cancelled {
		t.Error("Stop did not cancel the tracer's background work")
	}
	if tr.dnsPacketLinks != nil || tr.http3Links != nil || tr.containerUprobes != nil {
		t.Error("Stop left link registries populated")
	}
}
