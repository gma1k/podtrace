package tracer

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
	"github.com/gma1k/podtrace/internal/ebpf/h3stream"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func TestAContainerWhoseBinariesAllVanishedStillGetsOnePID(t *testing.T) {
	const cid = "0123456789ab0123456789ab0123456789ab0123456789ab0123456789ab0123"
	cgroupDir := fakeContainerProc(t, cid, []uint32{301, 302}, map[uint32]string{})
	tr := &Tracer{}
	tr.setCgroupPaths([]string{cgroupDir})

	if got := tr.pidsForContainer(cid, nil); len(got) != 1 || got[0] != 301 {
		t.Errorf("pidsForContainer = %v, want [301]: with no executable left to inspect, the "+
			"first process still gives uprobe discovery somewhere to start", got)
	}
}

func TestAnUnknownGroupAttachesNoContainerUprobes(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{}}
	if ls := tr.attachContainerGroupUprobes(probes.ProbeGroup("no-such-group"), "c1", []uint32{1}); ls != nil {
		t.Errorf("an unknown group attached %d links", len(ls))
	}
}

func TestReattachSkipsEmptyAttachesAndDropsLinksForAContainerThatChanged(t *testing.T) {
	tr := &Tracer{containerUprobes: map[string]*containerUprobeSet{
		"empty":   {pids: []uint32{1}},
		"nolinks": {pids: []uint32{2}},
		"moved":   {pids: []uint32{3}},
	}}
	var stale *fakeLink
	tr.attachContainerGroupFn = func(_ probes.ProbeGroup, id string, _ []uint32) []link.Link {
		switch id {
		case "empty":
			return nil
		case "moved":
			tr.probeGroupsMu.Lock()
			tr.containerUprobes["moved"].pids = []uint32{99}
			tr.probeGroupsMu.Unlock()
			stale = &fakeLink{}
			return []link.Link{stale}
		default:
			return []link.Link{&fakeLink{}}
		}
	}

	if got := tr.reattachContainerGroupUprobes(probes.GroupTLS); got != 1 {
		t.Errorf("reattached %d links, want 1 (only the container that stayed put)", got)
	}
	if len(tr.containerUprobes["nolinks"].links[probes.GroupTLS]) != 1 {
		t.Error("a container with no link map did not get its reattached link")
	}
	if stale.closes.Load() != 1 {
		t.Errorf("a link attached for a container whose processes changed meanwhile was closed "+
			"%d times, want 1; stored against the new PIDs it would probe the wrong binary",
			stale.closes.Load())
	}
}

func TestATxnWithNoStashOrConnectionIsNotParked(t *testing.T) {
	if (&Tracer{}).h3EnrichOrPark(&h3decode.Txn{AdapterConn: 1, IsClient: true}) {
		t.Error("parked a txn with no section stash to ever enrich it")
	}
	tr := &Tracer{h3SectionStash: h3stream.NewSectionStash(time.Minute, 16)}
	if tr.h3EnrichOrPark(&h3decode.Txn{AdapterConn: 0, IsClient: true}) {
		t.Error("parked a txn with no connection to key it on")
	}
}

func TestTheParkingLotIsBounded(t *testing.T) {
	tr := &Tracer{h3SectionStash: h3stream.NewSectionStash(time.Minute, 16)}
	for i := 0; i < h3MaxParked; i++ {
		tr.h3Parked = append(tr.h3Parked, h3ParkedTxn{})
	}
	if tr.h3EnrichOrPark(&h3decode.Txn{PID: 1, AdapterConn: 2, IsClient: true}) {
		t.Error("a txn was parked past h3MaxParked; the lot would grow without bound")
	}
}

func TestPIDNamespaceStatReportsWhenNeitherNamespaceIsReadable(t *testing.T) {
	orig := selfPIDNamespace
	selfPIDNamespace = "/nonexistent/ns/pid"
	t.Cleanup(func() { selfPIDNamespace = orig })

	if _, _, err := pidNamespaceStat(t.TempDir()); err == nil {
		t.Error("no error when neither the node's nor the agent's PID namespace could be read")
	}
}

type noStat struct{ os.FileInfo }

func (noStat) Sys() any { return nil }

func TestAFileInfoWithoutStatDataYieldsNoRecord(t *testing.T) {
	st, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statRecordOf(noStat{st}); err == nil {
		t.Error("a stat record was invented for a FileInfo without one")
	}
	if _, err := getCgroupIDFromPath("/nonexistent/cgroup"); err == nil {
		t.Error("a missing cgroup path returned an id")
	}
}

func TestAManagementAPIThatCannotListenReturns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() { (&Tracer{}).serveManagementAPI(context.Background(), port); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveManagementAPI did not return when its port was taken")
	}
}
