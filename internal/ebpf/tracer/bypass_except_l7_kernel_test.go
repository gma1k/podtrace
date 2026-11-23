//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func serveOneHTTPExchange(t *testing.T) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()

	served := make(chan error, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = c.Close() }()
		readRequestHead(t, c)
		_, err = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		served <- err
	}()

	c, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "GET /bypass HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestKernelBypassExceptL7ShipsOnlyServedResponses(t *testing.T) {
	for _, tc := range []struct {
		mode          kernelagg.Mode
		wantServerEvt bool
	}{
		{kernelagg.ModeBypass, false},
		{kernelagg.ModeBypassExceptL7, true},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			if err := rlimit.RemoveMemlock(); err != nil {
				t.Skipf("cannot raise memlock: %v", err)
			}
			tr, err := NewTracer()
			if err != nil {
				t.Skipf("cannot load the podtrace object here: %v", err)
			}
			t.Cleanup(func() { _ = tr.Stop() })
			tr.attachGlobalProtocolProbesOnce()
			own := ownCgroupID(t)
			if err := tr.collection.Maps["target_cgroup_ids"].Put(own, uint8(1)); err != nil {
				t.Fatalf("target this process: %v", err)
			}
			if err := tr.SetKernelAggregationMode(tc.mode); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := make(chan *events.Event, 1<<12)
			if err := tr.Start(ctx, ch); err != nil {
				t.Fatalf("Start: %v", err)
			}

			serveOneHTTPExchange(t)
			time.Sleep(300 * time.Millisecond)

			rows, err := tr.DrainKernelMetrics()
			if err != nil {
				t.Fatal(err)
			}
			var counted uint64
			for _, r := range rows {
				if r.Key.CgroupID == own && events.EventType(r.Key.EventType) == events.EventHTTPResp {
					counted += r.Value.Count
				}
			}
			if counted == 0 {
				t.Fatal("the kernel map never counted the HTTP response")
			}

			var served, called, sends int
			for drained := false; !drained; {
				select {
				case ev := <-ch:
					if ev.CgroupID != own {
						continue
					}
					switch {
					case ev.Type == events.EventHTTPResp && ev.IsServerL7Response():
						served++
						if !ev.KernelAggregated {
							t.Error("a shipped response the map already counted is not marked, so the plane counts it twice")
						}
					case ev.Type == events.EventHTTPResp:
						called++
					case ev.Type == events.EventTCPSend:
						sends++
					}
				default:
					drained = true
				}
			}
			if tc.wantServerEvt && served == 0 {
				t.Error("the served response never reached userspace, so its method and status code are lost")
			}
			if !tc.wantServerEvt && served != 0 {
				t.Errorf("%d served responses crossed the ring buffer with the bypass armed", served)
			}
			if called != 0 {
				t.Errorf("%d client-side responses crossed the ring buffer; nothing reads them without a PodTrace", called)
			}
			if sends != 0 {
				t.Errorf("%d tcp sends crossed the ring buffer; only L7 responses may skip the bypass", sends)
			}
		})
	}
}
