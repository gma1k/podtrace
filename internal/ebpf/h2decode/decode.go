// Package h2decode is the userspace HTTP/2 HPACK decode.

package h2decode

import (
	"encoding/binary"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/safeconv"
)

// recordHeaderSize is the fixed prefix of struct h2_hdr_record.
const recordHeaderSize = 48

// Flag bits mirror H2_HDR_FLAG_* in bpf/events.h.
const (
	flagEndHeaders   = 0x1
	flagContinuation = 0x2
	flagClose        = 0x4
)

// Direction values mirror H2_DIR_* in bpf/events.h.
const (
	DirEgress  uint8 = 0
	DirIngress uint8 = 1
)

// Tunables. Defaults chosen to bound memory under connection churn while
// tolerating realistic cross-CPU reordering.
const (
	defaultMaxConns         = 4096
	defaultMaxPendingPerDir = 64
	defaultMaxAssembly      = 64 * 1024
	defaultMaxStreams       = 8192
	defaultTTL              = 60 * time.Second
	defaultGapTimeout       = 2 * time.Second
	hpackMaxDynTableSize    = 4096
)

// RawRecord is a parsed struct h2_hdr_record plus its raw HPACK fragment.
type RawRecord struct {
	ConnID    uint64
	Timestamp uint64
	CgroupID  uint64
	PID       uint32
	Seq       uint32
	StreamID  uint32
	FragLen   uint16
	Direction uint8
	Transport uint8
	Flags     uint8
	Frag      []byte
}

func (r *RawRecord) endHeaders() bool { return r.Flags&flagEndHeaders != 0 }

func (r *RawRecord) IsClose() bool { return r.Flags&flagClose != 0 }

// ParseRecord decodes one ringbuf sample into a RawRecord.
func ParseRecord(data []byte) (*RawRecord, bool) {
	if len(data) < recordHeaderSize {
		return nil, false
	}
	fragLen := binary.LittleEndian.Uint16(data[36:38])
	if recordHeaderSize+int(fragLen) > len(data) {
		return nil, false
	}
	r := &RawRecord{
		ConnID:    binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: binary.LittleEndian.Uint64(data[8:16]),
		CgroupID:  binary.LittleEndian.Uint64(data[16:24]),
		PID:       binary.LittleEndian.Uint32(data[24:28]),
		Seq:       binary.LittleEndian.Uint32(data[28:32]),
		StreamID:  binary.LittleEndian.Uint32(data[32:36]),
		FragLen:   fragLen,
		Direction: data[38],
		Transport: data[39],
		Flags:     data[40],
	}
	if fragLen > 0 {
		r.Frag = make([]byte, fragLen)
		copy(r.Frag, data[recordHeaderSize:recordHeaderSize+int(fragLen)])
	}
	return r, true
}

type connKey struct {
	conn uint64
	dir  uint8
}

type streamKey struct {
	conn   uint64
	stream uint32
}

// dirState is the ordered decode state for one (connection, direction).
type dirState struct {
	dec      *hpack.Decoder
	nextSeq  uint32
	pending  map[uint32]*RawRecord
	asm      []byte
	lastSeen time.Time
	stalled  time.Time
}

// pendingReq is a request awaiting its response, for latency + endpoint stitching.
type pendingReq struct {
	method    string
	path      string
	transport uint8
	startTS   uint64
	lastSeen  time.Time
}

// Decoder owns all per-connection decode state.
type Decoder struct {
	mu      sync.Mutex
	dirs    map[connKey]*dirState
	streams map[streamKey]*pendingReq

	maxConns         int
	maxPendingPerDir int
	maxAssembly      int
	maxStreams       int
	ttl              time.Duration
	gapTimeout       time.Duration

	nowFn func() time.Time

	decodeErrors uint64
	gapsSkipped  uint64
	evictions    uint64
}

// New returns a Decoder with default tunables.
func New() *Decoder {
	return &Decoder{
		dirs:             make(map[connKey]*dirState),
		streams:          make(map[streamKey]*pendingReq),
		maxConns:         defaultMaxConns,
		maxPendingPerDir: defaultMaxPendingPerDir,
		maxAssembly:      defaultMaxAssembly,
		maxStreams:       defaultMaxStreams,
		ttl:              defaultTTL,
		gapTimeout:       defaultGapTimeout,
		nowFn:            time.Now,
	}
}

func (d *Decoder) now() time.Time { return d.nowFn() }

// Ingest feeds one raw record and returns any events whose header blocks
// completed and decoded as a result.
func (d *Decoder) Ingest(rec *RawRecord) []*events.Event {
	if rec == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	key := connKey{conn: rec.ConnID, dir: rec.Direction}
	st := d.dirs[key]
	if st == nil {
		d.evictIfFullLocked()
		st = &dirState{
			dec:     hpack.NewDecoder(hpackMaxDynTableSize, nil),
			nextSeq: 0,
			pending: make(map[uint32]*RawRecord),
		}
		d.dirs[key] = st
	}
	st.lastSeen = d.now()

	if seqLess(rec.Seq, st.nextSeq) {
		return nil
	}
	st.pending[rec.Seq] = rec

	if len(st.pending) > d.maxPendingPerDir {
		d.skipGapLocked(st)
	}

	return d.drainLocked(st)
}

// drainLocked releases buffered records in seq order, reassembles complete
// header blocks, and decodes them.
func (d *Decoder) drainLocked(st *dirState) []*events.Event {
	var out []*events.Event
	for {
		rec, ok := st.pending[st.nextSeq]
		if !ok {
			if len(st.pending) > 0 && st.stalled.IsZero() {
				st.stalled = d.now()
			}
			break
		}
		delete(st.pending, st.nextSeq)
		st.nextSeq++
		st.stalled = time.Time{}

		st.asm = append(st.asm, rec.Frag...)
		if len(st.asm) > d.maxAssembly {
			st.asm = nil
			d.decodeErrors++
			continue
		}
		if !rec.endHeaders() {
			continue
		}

		block := st.asm
		st.asm = nil
		if ev := d.decodeBlockLocked(st, rec, block); ev != nil {
			out = append(out, ev)
		}
	}
	return out
}

// decodeBlockLocked decodes one complete header block and builds an event.
func (d *Decoder) decodeBlockLocked(st *dirState, rec *RawRecord, block []byte) *events.Event {
	fields, err := st.dec.DecodeFull(block)
	if err != nil {
		d.decodeErrors++
		st.dec = hpack.NewDecoder(hpackMaxDynTableSize, nil)
		return nil
	}

	var method, path, status, traceparent string
	for _, f := range fields {
		switch {
		case f.Name == ":method":
			method = f.Value
		case f.Name == ":path":
			path = f.Value
		case f.Name == ":status":
			status = f.Value
		case strings.EqualFold(f.Name, "traceparent"):
			traceparent = f.Value
		}
	}

	switch {
	case path != "":
		return d.buildRequestLocked(rec, method, path, traceparent)
	case status != "":
		return d.buildResponseLocked(rec, status, traceparent)
	default:
		return nil
	}
}

func (d *Decoder) buildRequestLocked(rec *RawRecord, method, path, traceparent string) *events.Event {
	if method == "" {
		method = "GET"
	}
	d.rememberStreamLocked(rec, method, path)

	ev := &events.Event{}
	ev.Timestamp = rec.Timestamp
	ev.PID = rec.PID
	ev.CgroupID = rec.CgroupID
	ev.Type = events.EventHTTPReq
	ev.TCPState = uint32(rec.Transport)
	ev.Target = method + " " + path
	if traceparent != "" {
		ev.Details = "traceparent: " + traceparent
	}
	return ev
}

func (d *Decoder) buildResponseLocked(rec *RawRecord, status, traceparent string) *events.Event {
	ev := &events.Event{}
	ev.Timestamp = rec.Timestamp
	ev.PID = rec.PID
	ev.CgroupID = rec.CgroupID
	ev.Type = events.EventHTTPResp
	ev.TCPState = uint32(rec.Transport)
	ev.Details = status
	if code, err := strconv.Atoi(status); err == nil && code >= 500 && code <= 599 {
		ev.Error = safeconv.IntToInt32(code)
	}

	sk := streamKey{conn: rec.ConnID, stream: rec.StreamID}
	if req, ok := d.streams[sk]; ok {
		ev.Target = req.method + " " + req.path
		if rec.Timestamp > req.startTS {
			ev.LatencyNS = rec.Timestamp - req.startTS
		}
		delete(d.streams, sk)
	} else {
		ev.Target = status
	}
	if traceparent != "" && ev.Details == status {
		ev.Details = "traceparent: " + traceparent
	}
	return ev
}

func (d *Decoder) rememberStreamLocked(rec *RawRecord, method, path string) {
	if rec.StreamID == 0 {
		return
	}
	if len(d.streams) >= d.maxStreams {
		d.evictOldestStreamLocked()
	}
	d.streams[streamKey{conn: rec.ConnID, stream: rec.StreamID}] = &pendingReq{
		method:    method,
		path:      path,
		transport: rec.Transport,
		startTS:   rec.Timestamp,
		lastSeen:  d.now(),
	}
}

// skipGapLocked advances past the lowest missing seq so a lost fragment cannot
// stall the connection.
func (d *Decoder) skipGapLocked(st *dirState) {
	lowest, ok := lowestSeq(st.pending)
	if !ok {
		return
	}
	st.nextSeq = lowest
	st.asm = nil
	st.stalled = time.Time{}
	st.dec = hpack.NewDecoder(hpackMaxDynTableSize, nil)
	d.gapsSkipped++
}

// Sweep releases connections stuck behind a gap past the timeout and evicts
// idle state.
func (d *Decoder) Sweep() []*events.Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()

	var out []*events.Event
	for key, st := range d.dirs {
		if !st.stalled.IsZero() && now.Sub(st.stalled) > d.gapTimeout {
			d.skipGapLocked(st)
			out = append(out, d.drainLocked(st)...)
		}
		if now.Sub(st.lastSeen) > d.ttl {
			delete(d.dirs, key)
			d.evictions++
		}
	}
	for sk, req := range d.streams {
		if now.Sub(req.lastSeen) > d.ttl {
			delete(d.streams, sk)
		}
	}
	return out
}

// Evict drops all decode state for a connection (both directions) and its
// outstanding stream correlations.
func (d *Decoder) Evict(connID uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.dirs, connKey{conn: connID, dir: DirEgress})
	delete(d.dirs, connKey{conn: connID, dir: DirIngress})
	for sk := range d.streams {
		if sk.conn == connID {
			delete(d.streams, sk)
		}
	}
}

func (d *Decoder) evictIfFullLocked() {
	if len(d.dirs) < d.maxConns {
		return
	}
	var oldestKey connKey
	var oldest time.Time
	first := true
	for key, st := range d.dirs {
		if first || st.lastSeen.Before(oldest) {
			oldest = st.lastSeen
			oldestKey = key
			first = false
		}
	}
	if !first {
		delete(d.dirs, oldestKey)
		d.evictions++
	}
}

func (d *Decoder) evictOldestStreamLocked() {
	var oldestKey streamKey
	var oldest time.Time
	first := true
	for sk, req := range d.streams {
		if first || req.lastSeen.Before(oldest) {
			oldest = req.lastSeen
			oldestKey = sk
			first = false
		}
	}
	if !first {
		delete(d.streams, oldestKey)
	}
}

// Stats reports diagnostic counters.
type Stats struct {
	Conns        int
	Streams      int
	DecodeErrors uint64
	GapsSkipped  uint64
	Evictions    uint64
}

func (d *Decoder) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Stats{
		Conns:        len(d.dirs),
		Streams:      len(d.streams),
		DecodeErrors: d.decodeErrors,
		GapsSkipped:  d.gapsSkipped,
		Evictions:    d.evictions,
	}
}

// seqLess reports whether a is before b in u32 sequence space, tolerating
// wraparound.
func seqLess(a, b uint32) bool {
	return a-b >= 1<<31
}

func lowestSeq(m map[uint32]*RawRecord) (uint32, bool) {
	var lowest uint32
	found := false
	for s := range m {
		if !found || seqLess(s, lowest) {
			lowest = s
			found = true
		}
	}
	return lowest, found
}
