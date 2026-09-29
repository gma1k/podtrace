package tracer

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func decodedGRPC(pid uint32) *events.Event {
	return &events.Event{Type: events.EventHTTPResp, PID: pid, TCPState: 2, Details: "200\ngrpc-status: 0"}
}

func probeEvent(pid uint32, typ events.EventType) *events.Event {
	return &events.Event{Type: typ, PID: pid, TCPState: grpcGoProbeTransport}
}

func TestAProbeEventIsDroppedWhileTheDecoderSeesTheProcess(t *testing.T) {
	c := newGRPCDecodeCoverage()
	now := time.Now()
	if c.suppresses(probeEvent(7, events.EventHTTPResp), now) {
		t.Fatal("a probe event was dropped before the decoder saw the process")
	}
	c.noteDecoded(decodedGRPC(7), now)
	for _, typ := range []events.EventType{events.EventHTTPReq, events.EventHTTPResp} {
		if !c.suppresses(probeEvent(7, typ), now.Add(time.Second)) {
			t.Errorf("a %v probe event was kept for a process the decoder covers; the call would count twice", typ)
		}
	}
	if c.suppresses(probeEvent(8, events.EventHTTPResp), now) {
		t.Error("another process's probe event was dropped")
	}
	if c.suppresses(probeEvent(7, events.EventHTTPResp), now.Add(grpcCoverageTTL+time.Second)) {
		t.Error("coverage never expires; a process the decoder stopped seeing would lose its gRPC calls")
	}
}

func TestOnlyProbeHTTPEventsAreEverDropped(t *testing.T) {
	c := newGRPCDecodeCoverage()
	now := time.Now()
	c.noteDecoded(decodedGRPC(7), now)
	for _, ev := range []*events.Event{
		nil,
		{Type: events.EventHTTPResp, PID: 7, TCPState: 2},
		{Type: events.EventHTTPResp, PID: 7, TCPState: 1},
		{Type: events.EventTCPSend, PID: 7, TCPState: grpcGoProbeTransport},
	} {
		if c.suppresses(ev, now) {
			t.Errorf("dropped %+v", ev)
		}
	}
	var none *grpcDecodeCoverage
	none.noteDecoded(decodedGRPC(7), now)
	if none.suppresses(probeEvent(7, events.EventHTTPResp), now) {
		t.Error("a nil coverage dropped an event")
	}
}

func TestOnlyADecodedGRPCCallMarksAProcess(t *testing.T) {
	c := newGRPCDecodeCoverage()
	now := time.Now()
	c.noteDecoded(&events.Event{Type: events.EventHTTPResp, PID: 7, Details: "200"}, now)
	if c.suppresses(probeEvent(7, events.EventHTTPResp), now) {
		t.Error("a plain HTTP/2 response marked the process as gRPC-covered")
	}
}

func TestCoverageIsBoundedAndReclaimsStaleProcesses(t *testing.T) {
	c := newGRPCDecodeCoverage()
	now := time.Now()
	for pid := uint32(1); pid <= maxGRPCCoverageProcs; pid++ {
		c.noteDecoded(decodedGRPC(pid), now)
	}
	c.noteDecoded(decodedGRPC(maxGRPCCoverageProcs+1), now)
	if len(c.seen) != maxGRPCCoverageProcs {
		t.Fatalf("%d processes tracked against a bound of %d", len(c.seen), maxGRPCCoverageProcs)
	}
	c.noteDecoded(decodedGRPC(1), now.Add(time.Second))
	later := now.Add(grpcCoverageTTL + time.Minute)
	c.noteDecoded(decodedGRPC(maxGRPCCoverageProcs+1), later)
	if !c.suppresses(probeEvent(maxGRPCCoverageProcs+1, events.EventHTTPResp), later) {
		t.Error("a full map did not make room by dropping stale processes")
	}
}
