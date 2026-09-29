package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/gma1k/podtrace/internal/ebpf/h2decode"
	"github.com/gma1k/podtrace/internal/events"
)

type recordEncoder struct {
	buf bytes.Buffer
	enc *hpack.Encoder
}

func newRecordEncoder() *recordEncoder {
	e := &recordEncoder{}
	e.enc = hpack.NewEncoder(&e.buf)
	return e
}

func (e *recordEncoder) record(conn uint64, dir uint8, seq, stream uint32, flags uint8, fields ...hpack.HeaderField) []byte {
	e.buf.Reset()
	for _, f := range fields {
		_ = e.enc.WriteField(f)
	}
	frag := e.buf.Bytes()
	raw := make([]byte, 96+len(frag))
	le := binary.LittleEndian
	le.PutUint64(raw[0:], conn)
	le.PutUint64(raw[8:], 1000+uint64(seq))
	le.PutUint32(raw[24:], 77)
	le.PutUint32(raw[28:], seq)
	le.PutUint32(raw[32:], stream)
	le.PutUint16(raw[36:], uint16(len(frag)))
	raw[38] = dir
	raw[39] = 2
	raw[40] = flags
	copy(raw[96:], frag)
	return raw
}

func h2Tracer() *Tracer {
	tr := newDispatchTestTracer()
	tr.h2Decoder = h2decode.New()
	tr.grpcCoverage = newGRPCDecodeCoverage()
	return tr
}

func handleInto(tr *Tracer, raw []byte, ch chan *events.Event) {
	var collected, filtered, parsed atomic.Int64
	var filteringDisabled atomic.Bool
	tr.handleH2Record(context.Background(), raw, ch, nil, &eventCounters{
		collected: &collected, filtered: &filtered, parsed: &parsed, filteringDisabled: &filteringDisabled,
	})
}

func drain(ch chan *events.Event) []*events.Event {
	var out []*events.Event
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

const endHeaders, closeRecord = 0x1, 0x4

func TestARawGRPCCallReachesTheEventStreamOnceAndMarksItsProcess(t *testing.T) {
	tr := h2Tracer()
	ch := make(chan *events.Event, 8)
	req, resp := newRecordEncoder(), newRecordEncoder()
	grpc := hpack.HeaderField{Name: "content-type", Value: "application/grpc"}
	handleInto(tr, req.record(5, h2decode.DirIngress, 0, 1, endHeaders,
		hpack.HeaderField{Name: ":method", Value: "POST"}, hpack.HeaderField{Name: ":path", Value: "/pkg.Svc/Do"}, grpc), ch)
	handleInto(tr, resp.record(5, h2decode.DirEgress, 0, 1, endHeaders, hpack.HeaderField{Name: ":status", Value: "200"}, grpc), ch)
	handleInto(tr, resp.record(5, h2decode.DirEgress, 1, 1, endHeaders, hpack.HeaderField{Name: "grpc-status", Value: "0"}), ch)

	var responses int
	for _, ev := range drain(ch) {
		if ev.Type == events.EventHTTPResp {
			responses++
		}
	}
	if responses != 1 {
		t.Errorf("%d responses for one gRPC call", responses)
	}
	probe := &events.Event{Type: events.EventHTTPResp, PID: 77, TCPState: grpcGoProbeTransport}
	if !tr.grpcCoverage.suppresses(probe, time.Now()) {
		t.Error("the decoded call did not mark its process; the uprobe copy of the call would count too")
	}
}

func TestAClosedConnectionFlushesTheCallItHeld(t *testing.T) {
	tr := h2Tracer()
	ch := make(chan *events.Event, 8)
	resp := newRecordEncoder()
	handleInto(tr, resp.record(6, h2decode.DirEgress, 0, 1, endHeaders,
		hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "application/grpc"}), ch)
	if n := len(drain(ch)); n != 0 {
		t.Fatalf("a held response was dispatched %d times before its trailers", n)
	}
	handleInto(tr, newRecordEncoder().record(6, h2decode.DirEgress, 0, 0, closeRecord), ch)
	if evs := drain(ch); len(evs) != 1 || evs[0].Type != events.EventHTTPResp {
		t.Errorf("close dispatched %+v; the cut-off call counts once", evs)
	}
}

func TestAMalformedRecordIsDropped(t *testing.T) {
	tr := h2Tracer()
	ch := make(chan *events.Event, 1)
	handleInto(tr, []byte{1, 2, 3}, ch)
	if len(drain(ch)) != 0 {
		t.Error("a truncated record produced an event")
	}
}
