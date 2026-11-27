//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

const (
	dnsSprayWorkerCount = "PODTRACE_DNS_SPRAY_COUNT"
	dnsSprayWorkerFirst = "PODTRACE_DNS_SPRAY_FIRST_TXID"
	dnsBlackhole        = "127.0.0.9:53"
	dnsInflightBudget   = 4096
)

func TestKernelDNSSprayWorker(t *testing.T) {
	count := os.Getenv(dnsSprayWorkerCount)
	if count == "" {
		t.Skip("only runs as the child of the DNS in-flight budget kernel test")
	}
	n, err := strconv.Atoi(count)
	if err != nil {
		t.Fatal(err)
	}
	first, err := strconv.Atoi(os.Getenv(dnsSprayWorkerFirst))
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ResolveUDPAddr("udp", dnsBlackhole)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	for i := 0; i < n; i++ {
		if _, err := pc.WriteTo(dnsQuery(uint16(first+i), "spray.test"), server); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("done")
}

func inflightByCgroup(t *testing.T, tr *Tracer) map[uint64]int {
	t.Helper()
	out := map[uint64]int{}
	var key dnsFlowKey
	var val dnsQueryState
	iter := tr.collection.Maps["dns_inflight"].Iterate()
	for iter.Next(&key, &val) {
		out[key.CgroupID]++
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func dnsDropTotal(t *testing.T, tr *Tracer) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := tr.collection.Maps["dns_drops"].Lookup(uint32(0), &perCPU); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

func TestKernelOneCgroupsQuerySprayCannotEvictAnotherCgroupsQuery(t *testing.T) {
	victim := newFSWorker(t, "dns-victim")
	sprayer := newFSWorker(t, "dns-sprayer")
	tr := fsTracer(t, "fentry", victim, sprayer)
	if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
		t.Fatal(err)
	}

	runInCgroup(t, victim.cgroup, "TestKernelDNSSprayWorker", dnsSprayWorkerCount+"=1", dnsSprayWorkerFirst+"=30000")
	dropsBefore := dnsDropTotal(t, tr)
	const extra = 64
	runInCgroup(t, sprayer.cgroup, "TestKernelDNSSprayWorker",
		dnsSprayWorkerCount+"="+strconv.Itoa(dnsInflightBudget+extra), dnsSprayWorkerFirst+"=1")

	live := inflightByCgroup(t, tr)
	if live[victim.id] != 1 {
		t.Errorf("the victim's pending query is gone (%d left); another cgroup's spray evicted it", live[victim.id])
	}
	if live[sprayer.id] != dnsInflightBudget {
		t.Errorf("the sprayer holds %d in-flight queries, want exactly its budget of %d", live[sprayer.id], dnsInflightBudget)
	}
	var count int32
	if err := tr.collection.Maps[dnsInflightCountMapName].Lookup(sprayer.id, &count); err != nil || count != dnsInflightBudget {
		t.Errorf("the sprayer's in-flight count is %d (%v), want %d", count, err, dnsInflightBudget)
	}
	if drops := dnsDropTotal(t, tr) - dropsBefore; drops < extra {
		t.Errorf("%d drops counted, want at least the %d queries refused past the budget", drops, extra)
	}

	tr.syncDNSInflightCounts(map[uint64]int32{victim.id: 1})
	if err := tr.collection.Maps[dnsInflightCountMapName].Lookup(sprayer.id, &count); err == nil {
		t.Errorf("a cgroup with nothing left in flight keeps a count of %d after the sweep", count)
	}
}
