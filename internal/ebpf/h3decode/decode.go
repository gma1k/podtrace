// Package h3decode turns one HTTP/3 transaction record (emitted by
// bpf/http3l7.c from the net/http boundary) into a paired EventHTTPReq +
// EventHTTPResp.
package h3decode

import (
	"encoding/binary"
	"strconv"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/safeconv"
)

// Offsets mirror struct h3_txn_record in bpf/events.h.
const (
	methodMax    = 16  // H3_TXN_METHOD_MAX
	pathMax      = 256 // H3_TXN_PATH_MAX
	tpMax        = 64  // H3_TXN_TP_MAX
	methodOffset = 40  // start of method[]
	pathOffset   = methodOffset + methodMax
	tpOffset     = pathOffset + pathMax
	recordSize   = tpOffset + tpMax
)

// Txn is one decoded HTTP/3 transaction.
type Txn struct {
	Timestamp   uint64
	LatencyNS   uint64
	CgroupID    uint64
	PID         uint32
	Status      uint16
	IsClient    bool
	Method      string
	Path        string
	Traceparent string
}

// ParseRecord decodes one ringbuf sample into a Txn.
func ParseRecord(data []byte) (*Txn, bool) {
	if len(data) < recordSize {
		return nil, false
	}
	methodLen := int(data[31])
	if methodLen > methodMax {
		methodLen = methodMax
	}
	pathLen := int(binary.LittleEndian.Uint16(data[32:34]))
	if pathLen > pathMax {
		pathLen = pathMax
	}
	tpLen := int(data[34])
	if tpLen > tpMax {
		tpLen = tpMax
	}
	return &Txn{
		Timestamp:   binary.LittleEndian.Uint64(data[0:8]),
		LatencyNS:   binary.LittleEndian.Uint64(data[8:16]),
		CgroupID:    binary.LittleEndian.Uint64(data[16:24]),
		PID:         binary.LittleEndian.Uint32(data[24:28]),
		Status:      binary.LittleEndian.Uint16(data[28:30]),
		IsClient:    data[30] != 0,
		Method:      string(data[methodOffset : methodOffset+methodLen]),
		Path:        string(data[pathOffset : pathOffset+pathLen]),
		Traceparent: string(data[tpOffset : tpOffset+tpLen]),
	}, true
}

// Events turns a transaction into the request and response events that flow
// through the same enrichment + reporting path as other L7 events.
func (t *Txn) Events() []*events.Event {
	method := t.Method
	if method == "" {
		method = "GET"
	}
	target := method + " " + t.Path
	status := strconv.Itoa(int(t.Status))

	req := &events.Event{
		Timestamp: t.Timestamp,
		PID:       t.PID,
		CgroupID:  t.CgroupID,
		Type:      events.EventHTTPReq,
		TCPState:  events.HTTPTransportH3,
		Target:    target,
	}
	if t.Traceparent != "" {
		req.Details = "traceparent: " + t.Traceparent
	}
	resp := &events.Event{
		Timestamp: t.Timestamp + t.LatencyNS,
		PID:       t.PID,
		CgroupID:  t.CgroupID,
		Type:      events.EventHTTPResp,
		TCPState:  events.HTTPTransportH3,
		Target:    target,
		Details:   status,
		LatencyNS: t.LatencyNS,
	}
	if t.Status >= 500 && t.Status <= 599 {
		resp.Error = safeconv.IntToInt32(int(t.Status))
	}
	return []*events.Event{req, resp}
}
