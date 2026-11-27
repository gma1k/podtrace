//go:build bpf_loadtest && linux

package tracer

import (
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

func v4Mapped(ip net.IP) [16]byte {
	var a [16]byte
	copy(a[:], ip.To16())
	return a
}

func socket6(t *testing.T, typ int, v6only bool) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no AF_INET6 sockets here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	flag := 0
	if v6only {
		flag = 1
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, flag); err != nil {
		t.Fatal(err)
	}
	return fd
}

func socket4(t *testing.T, typ int) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func boundPort(t *testing.T, fd int) int {
	t.Helper()
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return a.Port
	case *unix.SockaddrInet6:
		return a.Port
	}
	t.Fatalf("unexpected socket address %T", sa)
	return 0
}

func networkLog(t *testing.T, keep func(*events.Event) bool) *eventLog {
	t.Helper()
	return traceGroup(t, probes.GroupNetwork, keep)
}

func settle(log *eventLog) []*events.Event {
	time.Sleep(time.Second)
	return log.events()
}

func TestKernelAV4MappedConnectIsOneConnectToTheIPv4Peer(t *testing.T) {
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := lis.Addr().(*net.TCPAddr).Port
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	log := networkLog(t, func(ev *events.Event) bool { return ev.Type == events.EventConnect })

	const connects = 3
	for i := 0; i < connects; i++ {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Skipf("no AF_INET6 sockets here: %v", err)
		}
		err = unix.Connect(fd, &unix.SockaddrInet6{Port: port, Addr: v4Mapped(net.IPv4(127, 0, 0, 1))})
		_ = unix.Close(fd)
		if err != nil {
			t.Fatalf("connect over a dual-stack socket: %v", err)
		}
	}
	refused := socket6(t, unix.SOCK_STREAM, true)
	if err := unix.Connect(refused, &unix.SockaddrInet6{Port: port, Addr: v4Mapped(net.IPv4(127, 0, 0, 1))}); err == nil {
		t.Fatal("an IPv6-only socket connected to a v4-mapped peer")
	}

	ok, failed := 0, 0
	for _, ev := range settle(log) {
		switch ev.Target {
		case target:
			if ev.Error == 0 {
				ok++
			} else {
				failed++
			}
		default:
			if ev.PID == uint32(unix.Getpid()) && ev.Error == 0 {
				t.Errorf("connect reported as %q, want the IPv4 form %q", ev.Target, target)
			}
		}
	}
	if ok != connects {
		t.Errorf("%d successful connects reported for %d connect(2) calls; the nested tcp_v4_connect must not add its own", ok, connects)
	}
	if failed != 1 {
		t.Errorf("%d failed connects reported, want the IPv6-only socket's refusal once", failed)
	}
}

func TestKernelUDPOverIPv6IsTracedBothWays(t *testing.T) {
	recv := socket6(t, unix.SOCK_DGRAM, true)
	if err := unix.Bind(recv, &unix.SockaddrInet6{Addr: [16]byte{15: 1}}); err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	send := socket6(t, unix.SOCK_DGRAM, true)
	if err := unix.Bind(send, &unix.SockaddrInet6{Addr: [16]byte{15: 1}}); err != nil {
		t.Fatal(err)
	}
	rport, sport := boundPort(t, recv), boundPort(t, send)
	log := networkLog(t, func(ev *events.Event) bool {
		return ev.Type == events.EventUDPSend || ev.Type == events.EventUDPRecv
	})

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Sendto(send, []byte("ping"), 0, &unix.SockaddrInet6{Port: rport, Addr: [16]byte{15: 1}}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, _, err := unix.Recvfrom(recv, buf, 0); err != nil {
		t.Fatal(err)
	}

	var sent, received bool
	for _, ev := range settle(log) {
		if ev.Type == events.EventUDPSend && ev.PeerDstPort == uint16(rport) && ev.PeerDstIP == "::1" && ev.Bytes == 4 {
			sent = true
		}
		if ev.Type == events.EventUDPRecv && ev.PeerDstPort == uint16(sport) && ev.PeerDstIP == "::1" && ev.Bytes == 4 {
			received = true
		}
	}
	if !sent {
		t.Error("no UDP_SEND to [::1] from an AF_INET6 socket")
	}
	if !received {
		t.Error("no UDP_RECV from [::1] on an AF_INET6 socket")
	}
}

func TestKernelADualStackUDPSocketToAnIPv4PeerIsCountedOnce(t *testing.T) {
	recv4 := socket4(t, unix.SOCK_DGRAM)
	if err := unix.Bind(recv4, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	send6 := socket6(t, unix.SOCK_DGRAM, false)
	recv6 := socket6(t, unix.SOCK_DGRAM, false)
	if err := unix.Bind(recv6, &unix.SockaddrInet6{}); err != nil {
		t.Fatal(err)
	}
	send4 := socket4(t, unix.SOCK_DGRAM)
	if err := unix.Bind(send4, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	rport4, rport6, sport4 := boundPort(t, recv4), boundPort(t, recv6), boundPort(t, send4)
	log := networkLog(t, func(ev *events.Event) bool {
		return ev.Type == events.EventUDPSend || ev.Type == events.EventUDPRecv
	})

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const sends = 3
	for i := 0; i < sends; i++ {
		if err := unix.Sendto(send6, []byte("ping"), 0, &unix.SockaddrInet6{Port: rport4, Addr: v4Mapped(net.IPv4(127, 0, 0, 1))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Sendto(send4, []byte("pong"), 0, &unix.SockaddrInet4{Port: rport6, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, _, err := unix.Recvfrom(recv6, buf, 0); err != nil {
		t.Fatal(err)
	}

	mappedSends, mappedRecv := 0, false
	for _, ev := range settle(log) {
		if ev.Type == events.EventUDPSend && ev.PeerDstPort == uint16(rport4) {
			mappedSends++
			if ev.PeerDstIP != "127.0.0.1" {
				t.Errorf("v4-mapped send has peer %q, want 127.0.0.1", ev.PeerDstIP)
			}
		}
		if ev.Type == events.EventUDPRecv && ev.PeerDstPort == uint16(sport4) && ev.PeerDstIP == "127.0.0.1" {
			mappedRecv = true
		}
	}
	if mappedSends != sends {
		t.Errorf("%d UDP_SEND events for %d sendto(2) calls; udpv6_sendmsg falls through to udp_sendmsg and only one may report", mappedSends, sends)
	}
	if !mappedRecv {
		t.Error("a dual-stack socket's receive from an IPv4 peer was not traced")
	}
}

func TestKernelASendBeforeTheSocketHasAPeerDoesNotBorrowTheLastOne(t *testing.T) {
	first, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	fastOpen, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fastOpen.Close() }()
	for _, l := range []net.Listener{first, fastOpen} {
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					_, _ = c.Read(make([]byte, 64))
					_ = c.Close()
				}()
			}
		}(l)
	}
	firstPort := first.Addr().(*net.TCPAddr).Port
	fastOpenPort := fastOpen.Addr().(*net.TCPAddr).Port
	log := networkLog(t, func(ev *events.Event) bool { return ev.Type == events.EventTCPSend })

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uint32(unix.Gettid())
	connected := socket4(t, unix.SOCK_STREAM)
	if err := unix.Connect(connected, &unix.SockaddrInet4{Port: firstPort, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(connected, []byte("first")); err != nil {
		t.Fatal(err)
	}
	unconnected := socket4(t, unix.SOCK_STREAM)
	if err := unix.Sendto(unconnected, []byte("fastopen"), unix.MSG_FASTOPEN, &unix.SockaddrInet4{Port: fastOpenPort, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skipf("TCP Fast Open is not available here: %v", err)
	}

	var firstSeen, fastOpenSeen bool
	for _, ev := range settle(log) {
		if ev.Bytes == 5 && ev.PeerDstPort == uint16(firstPort) {
			firstSeen = true
		}
		if ev.Bytes == 8 {
			fastOpenSeen = true
			if ev.PeerDstPort == uint16(firstPort) {
				t.Errorf("thread %d: the fast-open send to port %d carries the previous send's peer port %d", tid, fastOpenPort, firstPort)
			}
		}
	}
	if !firstSeen || !fastOpenSeen {
		t.Skipf("sends not observed (first %v, fast open %v)", firstSeen, fastOpenSeen)
	}
}
