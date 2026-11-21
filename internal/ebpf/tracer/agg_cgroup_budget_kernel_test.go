//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	aggBudgetWorkerEnv = "PODTRACE_AGG_BUDGET_WORKER"
	aggBudgetPeers     = 8
)

func TestKernelAggBudgetWorker(t *testing.T) {
	if os.Getenv(aggBudgetWorkerEnv) == "" {
		t.Skip("only runs as the child of the aggregation budget kernel tests")
	}
	var sinks []net.PacketConn
	for i := 0; i < aggBudgetPeers; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pc.Close() }()
		sinks = append(sinks, pc)
	}
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	for _, sink := range sinks {
		if _, err := sender.WriteTo([]byte("x"), sink.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("done")
}

func aggBudgetTracer(t *testing.T, budget int, w fsWorker) *Tracer {
	t.Helper()
	orig := config.WorkloadMetricsContainerRowBudget
	config.WorkloadMetricsContainerRowBudget = budget
	t.Cleanup(func() { config.WorkloadMetricsContainerRowBudget = orig })
	tr := fsTracer(t, "fentry", w)
	for name, attach := range map[string]func(string, *link.KprobeOptions) (link.Link, error){
		"kprobe_udp_sendmsg": func(symbol string, opts *link.KprobeOptions) (link.Link, error) {
			return link.Kprobe(symbol, tr.collection.Programs["kprobe_udp_sendmsg"], opts)
		},
		"kretprobe_udp_sendmsg": func(symbol string, opts *link.KprobeOptions) (link.Link, error) {
			return link.Kretprobe(symbol, tr.collection.Programs["kretprobe_udp_sendmsg"], opts)
		},
	} {
		l, err := attach("udp_sendmsg", nil)
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
		t.Fatal(err)
	}
	return tr
}

func udpSendPeers(t *testing.T, tr *Tracer, cgroup uint64) (map[string]uint64, uint64) {
	t.Helper()
	rows, err := tr.DrainKernelMetrics()
	if err != nil {
		t.Fatal(err)
	}
	peers := map[string]uint64{}
	var total uint64
	for _, r := range rows {
		if r.Key.CgroupID != cgroup || events.EventType(r.Key.EventType) != events.EventUDPSend {
			continue
		}
		total += r.Value.Count
		peers[fmt.Sprintf("%s:%d", r.Key.PeerIP(), r.Key.PeerPort)] += r.Value.Count
	}
	return peers, total
}

func TestKernelACgroupPastItsRowBudgetKeepsCountsButLosesThePeer(t *testing.T) {
	w := newFSWorker(t, "agg-budget")
	tr := aggBudgetTracer(t, 2, w)

	for round := 0; round < 2; round++ {
		runInCgroup(t, w.cgroup, "TestKernelAggBudgetWorker", aggBudgetWorkerEnv+"=1")
		peers, total := udpSendPeers(t, tr, w.id)
		if total != aggBudgetPeers {
			t.Fatalf("round %d: %d sends counted, want all %d: past the budget only the peer may be dropped", round, total, aggBudgetPeers)
		}
		named := 0
		for peer := range peers {
			if peer != ":0" {
				named++
			}
		}
		if named != 2 || peers[":0"] != aggBudgetPeers-2 {
			t.Fatalf("round %d: peers %v, want 2 named and %d folded onto the peer-less row; "+
				"a second round that folds everything means the drain did not start a new budget interval",
				round, peers, aggBudgetPeers-2)
		}
	}
	if got := tr.KernelAggregationPressure().PeerCollapsed; got < 2*(aggBudgetPeers-2) {
		t.Errorf("peer collapsed = %d, want at least %d", got, 2*(aggBudgetPeers-2))
	}
}

func TestKernelAZeroRowBudgetKeepsEveryPeer(t *testing.T) {
	w := newFSWorker(t, "agg-nobudget")
	tr := aggBudgetTracer(t, 0, w)

	runInCgroup(t, w.cgroup, "TestKernelAggBudgetWorker", aggBudgetWorkerEnv+"=1")
	peers, total := udpSendPeers(t, tr, w.id)
	if total != aggBudgetPeers || len(peers) != aggBudgetPeers || peers[":0"] != 0 {
		t.Fatalf("peers %v (total %d), want each of the %d peers on its own row", peers, total, aggBudgetPeers)
	}
}
