//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

const (
	hostnameWorkerServer = "PODTRACE_HOSTNAME_WORKER_SERVER"
	hostnameWorkerCount  = "PODTRACE_HOSTNAME_WORKER_COUNT"
	hostnameWorkerFirst  = "PODTRACE_HOSTNAME_WORKER_FIRST_TXID"
	hostnameWorkerName   = "PODTRACE_HOSTNAME_WORKER_NAME"
)

func answeredIP(txid uint16) [4]byte {
	return [4]byte{10, 77, byte(txid >> 8), byte(txid)}
}

func serveARecords(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1:53: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = pc.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			resp := append([]byte(nil), buf[:n]...)
			binary.BigEndian.PutUint16(resp[2:4], 0x8180)
			binary.BigEndian.PutUint16(resp[6:8], 1)
			ip := answeredIP(binary.BigEndian.Uint16(buf[0:2]))
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			resp = append(resp, ip[:]...)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestKernelHostnameWorker(t *testing.T) {
	server := os.Getenv(hostnameWorkerServer)
	if server == "" {
		t.Skip("only runs as the child of the hostname cache kernel test")
	}
	n, err := strconv.Atoi(os.Getenv(hostnameWorkerCount))
	if err != nil {
		t.Fatal(err)
	}
	first, err := strconv.Atoi(os.Getenv(hostnameWorkerFirst))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	reply := make([]byte, 512)
	for i := 0; i < n; i++ {
		if _, err := conn.Write(dnsQuery(uint16(first+i), os.Getenv(hostnameWorkerName))); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(reply); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	fmt.Println("done")
}

func hostnamesByCgroup(t *testing.T, tr *Tracer) (map[uint64]int, map[uint64]map[[4]byte]string) {
	t.Helper()
	counts := map[uint64]int{}
	names := map[uint64]map[[4]byte]string{}
	var key [16]byte
	var val [dnsResolvedValueLen]byte
	iter := tr.collection.Maps["dns_resolved"].Iterate()
	for iter.Next(&key, &val) {
		cg := binary.NativeEndian.Uint64(key[0:8])
		counts[cg]++
		if names[cg] == nil {
			names[cg] = map[[4]byte]string{}
		}
		names[cg][[4]byte(key[8:12])] = string(bytes.TrimRight(val[:dnsResolvedNameLen], "\x00"))
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	return counts, names
}

func TestKernelOnePodsLookupsCannotPushOutAnotherPodsHostnames(t *testing.T) {
	orig := config.DNSPayloadEnabled
	config.DNSPayloadEnabled = false
	t.Cleanup(func() { config.DNSPayloadEnabled = orig })
	victim := newFSWorker(t, "hostname-victim")
	noisy := newFSWorker(t, "hostname-noisy")
	server := serveARecords(t)
	tr := fsTracer(t, "fentry", victim, noisy)
	if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
		t.Fatal(err)
	}

	const victimTxID = 60000
	runInCgroup(t, victim.cgroup, "TestKernelHostnameWorker", hostnameWorkerServer+"="+server,
		hostnameWorkerCount+"=1", hostnameWorkerFirst+"="+strconv.Itoa(victimTxID), hostnameWorkerName+"=victim.test")
	dropsBefore := dnsDropTotal(t, tr)
	const extra = 64
	runInCgroup(t, noisy.cgroup, "TestKernelHostnameWorker", hostnameWorkerServer+"="+server,
		hostnameWorkerCount+"="+strconv.Itoa(dnsResolvedCgroupBudget+extra), hostnameWorkerFirst+"=1", hostnameWorkerName+"=noisy.test")

	if dnsDropTotal(t, tr) == dropsBefore {
		t.Error("nothing reads the event ring here, yet no answer was dropped; the ring never filled")
	}
	counts, names := hostnamesByCgroup(t, tr)
	if got := names[victim.id][answeredIP(victimTxID)]; got != "victim.test" {
		t.Errorf("the victim's hostname is %q after another pod resolved %d names", got, dnsResolvedCgroupBudget+extra)
	}
	if counts[noisy.id] != dnsResolvedCgroupBudget {
		t.Errorf("the noisy pod holds %d hostnames, want exactly its budget of %d", counts[noisy.id], dnsResolvedCgroupBudget)
	}
	for txid := uint16(1); txid <= extra; txid++ {
		if _, ok := names[noisy.id][answeredIP(txid)]; ok {
			t.Errorf("the noisy pod's oldest hostname (txid %d) survived its own newer lookups", txid)
			break
		}
	}
	if got := names[noisy.id][answeredIP(dnsResolvedCgroupBudget+extra)]; got != "noisy.test" {
		t.Errorf("the noisy pod's newest hostname is %q", got)
	}

	cache := newDNSNameCache(tr.collection)
	ip := net.IP{10, 78, 0, 1}
	cache.rememberV4(noisy.id, ip, "decoded.test")
	if counts, names = hostnamesByCgroup(t, tr); names[noisy.id][[4]byte(ip)] != "decoded.test" {
		t.Error("the decoder's hostname was not stored")
	}
	if counts[noisy.id] != dnsResolvedCgroupBudget+1 {
		t.Errorf("the noisy pod holds %d hostnames after one decoder write, want %d", counts[noisy.id], dnsResolvedCgroupBudget+1)
	}
}
