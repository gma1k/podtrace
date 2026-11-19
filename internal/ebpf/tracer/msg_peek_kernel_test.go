//go:build bpf_loadtest && linux

package tracer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/events"
)

func serveOneRequest(t *testing.T, path string, peek bool) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	done := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			done <- err
			return
		}
		buf := make([]byte, 512)
		if peek {
			time.Sleep(50 * time.Millisecond)
			var peekErr error
			if err := raw.Read(func(fd uintptr) bool {
				_, _, peekErr = syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK)
				return peekErr != syscall.EAGAIN
			}); err != nil {
				done <- err
				return
			}
			if peekErr != nil {
				done <- peekErr
				return
			}
		}
		if _, err := conn.Read(buf); err != nil {
			done <- err
			return
		}
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		done <- err
	}()

	client, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if _, err := fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: peek.test\r\n\r\n", path); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(make([]byte, 128))
}

func TestKernelAPeekedHTTPRequestIsReportedOnce(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	tr.attachGlobalProtocolProbesOnce()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *events.Event, 1<<14)
	if err := tr.Start(ctx, ch); err != nil {
		t.Fatalf("Start: %v", err)
	}

	stamp := time.Now().UnixNano()
	control := fmt.Sprintf("/control-%d", stamp)
	peeked := fmt.Sprintf("/peeked-%d", stamp)
	serveOneRequest(t, control, false)
	serveOneRequest(t, peeked, true)
	time.Sleep(time.Second)

	counts := map[string]int{}
	for drained := false; !drained; {
		select {
		case ev := <-ch:
			if ev.Type != events.EventHTTPReq {
				continue
			}
			for _, p := range []string{control, peeked} {
				if strings.Contains(ev.Target, p) {
					counts[p]++
				}
			}
		default:
			drained = true
		}
	}
	if counts[control] == 0 {
		t.Fatalf("no request events for the control connection: %v", counts)
	}
	if counts[peeked] != counts[control] {
		t.Fatalf("peeked request reported %d times, control %d times", counts[peeked], counts[control])
	}
}
