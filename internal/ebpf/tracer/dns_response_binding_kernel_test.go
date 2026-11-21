//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

const (
	dnsBindingWorkerServers = "PODTRACE_DNS_BINDING_WORKER_SERVERS"
	dnsBindingDecoyTxID     = 0x2001
	dnsBindingSpoofTxID     = 0x2002
	dnsBindingFallbackTxID  = 0x2003
)

func TestKernelDNSBindingWorker(t *testing.T) {
	servers := os.Getenv(dnsBindingWorkerServers)
	if servers == "" {
		t.Skip("only runs as the child of the DNS response binding kernel tests")
	}
	parts := strings.Split(servers, ",")
	primary, err := net.ResolveUDPAddr("udp", parts[0])
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := net.ResolveUDPAddr("udp", parts[1])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	listen := func() net.PacketConn {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return pc
	}
	awaitFrom := func(pc net.PacketConn, from *net.UDPAddr) {
		buf := make([]byte, 512)
		deadline := time.Now().Add(2 * time.Second)
		for {
			_ = pc.SetReadDeadline(deadline)
			_, addr, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatalf("no answer from %s: %v", from, err)
			}
			if addr.String() == from.String() {
				return
			}
		}
	}

	decoy := listen()
	defer func() { _ = decoy.Close() }()
	main := listen()
	defer func() { _ = main.Close() }()
	if _, err := decoy.WriteTo(dnsQuery(dnsBindingDecoyTxID, "decoy.test"), primary); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := main.WriteTo(dnsQuery(dnsBindingSpoofTxID, "spoof.test"), primary); err != nil {
		t.Fatal(err)
	}
	awaitFrom(main, primary)

	first := listen()
	defer func() { _ = first.Close() }()
	second := listen()
	defer func() { _ = second.Close() }()
	if _, err := first.WriteTo(dnsQuery(dnsBindingFallbackTxID, "fallback.test"), primary); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := second.WriteTo(dnsQuery(dnsBindingFallbackTxID, "fallback.test"), fallback); err != nil {
		t.Fatal(err)
	}
	awaitFrom(second, fallback)
	fmt.Println("done")
}

func dnsBindingListen(t *testing.T, addr string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	return pc
}

func dnsAnswer(query []byte, rcode uint16) []byte {
	resp := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180|rcode)
	return resp
}

func serveSpoofedDNS(t *testing.T) (string, string) {
	t.Helper()
	primary := dnsBindingListen(t, "127.0.0.1:53")
	spoofer := dnsBindingListen(t, "127.0.0.2:53")
	fallback := dnsBindingListen(t, "127.0.0.3:53")
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = primary.Close()
		_ = spoofer.Close()
		_ = fallback.Close()
		wg.Wait()
	})

	wg.Add(2)
	go func() {
		defer wg.Done()
		var decoyAddr net.Addr
		buf := make([]byte, 512)
		for {
			n, addr, err := primary.ReadFrom(buf)
			if err != nil {
				return
			}
			query := buf[:n]
			switch qnameOf(query) {
			case "decoy.test":
				decoyAddr = addr
			case "spoof.test":
				if decoyAddr != nil {
					_, _ = primary.WriteTo(dnsAnswer(query, 2), decoyAddr)
				}
				_, _ = spoofer.WriteTo(dnsAnswer(query, 3), addr)
				time.Sleep(20 * time.Millisecond)
				_, _ = primary.WriteTo(dnsAnswer(query, 0), addr)
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 512)
		for {
			n, addr, err := fallback.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = fallback.WriteTo(dnsAnswer(buf[:n], 0), addr)
		}
	}()
	return primary.LocalAddr().String(), fallback.LocalAddr().String()
}

func TestKernelADNSAnswerCountsOnlyFromTheQueriedServerToTheQueryingPort(t *testing.T) {
	w := newFSWorker(t, "dns-binding")
	primary, fallback := serveSpoofedDNS(t)
	tr := dnsTracer(t, false, w)
	runInCgroup(t, w.cgroup, "TestKernelDNSBindingWorker", dnsBindingWorkerServers+"="+primary+","+fallback)

	rows, err := tr.DrainKernelMetrics()
	if err != nil {
		t.Fatal(err)
	}
	counts, failed, _ := dnsRows(t, rows, w.id)
	if counts[events.DNSAnswerNoError] != 2 || len(counts) != 1 || failed != 0 {
		t.Fatalf("answers %v (failed %d), want only the two genuine NOERROR answers: "+
			"a SERVFAIL means a response to another socket in the pod matched the query, "+
			"an NXDOMAIN means a response from an address the query never went to matched it, "+
			"a missing NOERROR means a query resent to a fallback server lost its answer", counts, failed)
	}
}
