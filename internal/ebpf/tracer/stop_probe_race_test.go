package tracer

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func TestSetContainerTargets_StopDuringAttach_NoPanicNoLeak(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var attached []*fakeLink

	tr.attachContainerGroupFn = func(g probes.ProbeGroup, id string, pids []uint32) []link.Link {
		once.Do(func() { close(started) })
		<-release
		l := &fakeLink{}
		attached = append(attached, l)
		return []link.Link{l}
	}

	done := make(chan error, 1)
	go func() {
		done <- tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{1}}})
	}()

	<-started
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}

	tr.probeGroupsMu.Lock()
	cu := tr.containerUprobes
	tr.probeGroupsMu.Unlock()
	if cu != nil {
		t.Errorf("containerUprobes must stay nil after Stop raced the attach, got %v", cu)
	}

	if len(attached) == 0 {
		t.Fatal("expected the raced attach to have produced links")
	}
	for i, l := range attached {
		if got := l.closes.Load(); got != 1 {
			t.Errorf("attached link %d closes = %d, want 1 (links attached after Stop must be closed, not leaked)", i, got)
		}
	}
}

func TestSetContainerTargets_AfterStop_NoResurrection(t *testing.T) {
	var attachCalls atomic.Int32
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
	tr.attachContainerGroupFn = func(g probes.ProbeGroup, id string, pids []uint32) []link.Link {
		attachCalls.Add(1)
		return []link.Link{&fakeLink{}}
	}

	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{1}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}

	tr.probeGroupsMu.Lock()
	cu := tr.containerUprobes
	tr.probeGroupsMu.Unlock()
	if cu != nil {
		t.Errorf("containerUprobes must stay nil after Stop, got %v", cu)
	}
	if got := attachCalls.Load(); got != 0 {
		t.Errorf("no probes should be attached after Stop, got %d attach calls", got)
	}
}

func TestSyncDNSPacketProbes_AfterStop_NoResurrection(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}, collection: &ebpf.Collection{}}
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	tr.syncDNSPacketProbes([]string{"/sys/fs/cgroup/kubepods/podx/containery"})

	tr.probeGroupsMu.Lock()
	m := tr.dnsPacketLinks
	tr.probeGroupsMu.Unlock()
	if m != nil {
		t.Errorf("dnsPacketLinks must stay nil after Stop, got %v", m)
	}
}

func TestSyncHTTP3Probes_AfterStop_NoResurrection(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}, collection: &ebpf.Collection{}}
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	tr.syncHTTP3Probes([]string{"/sys/fs/cgroup/kubepods/podx/containery"})

	tr.probeGroupsMu.Lock()
	m := tr.http3Links
	tr.probeGroupsMu.Unlock()
	if m != nil {
		t.Errorf("http3Links must stay nil after Stop, got %v", m)
	}
}

func TestRegisterGroupLinks_AfterStop_ClosesInsteadOfRegistering(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	l := &fakeLink{}
	tr.registerGroupLinks(probes.GroupTLS, []link.Link{l})

	if got := l.closes.Load(); got != 1 {
		t.Errorf("link closes = %d, want 1 (registerGroupLinks must close, not register, after Stop)", got)
	}
	tr.probeGroupsMu.Lock()
	groupLen := len(tr.probeGroups[probes.GroupTLS])
	flatLen := len(tr.links)
	tr.probeGroupsMu.Unlock()
	if groupLen != 0 {
		t.Errorf("probeGroups[TLS] gained %d links after Stop, want 0", groupLen)
	}
	if flatLen != 0 {
		t.Errorf("links registry gained %d handles after Stop, want 0", flatLen)
	}
}

func TestProbe_RealStopVsSetContainerTargets(t *testing.T) {
	for i := 0; i < 300; i++ {
		tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
		tr.attachContainerGroupFn = func(g probes.ProbeGroup, id string, pids []uint32) []link.Link {
			runtime.Gosched()
			return []link.Link{&fakeLink{}}
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = tr.Stop()
		}()
		go func() {
			defer wg.Done()
			_ = tr.SetContainerIDs([]string{"containeraaaa"})
		}()
		wg.Wait()
	}
}
