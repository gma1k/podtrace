package h3stream

import (
	"testing"
	"time"
)

func partialHeaders(size int) []byte {
	out := appendVarint(nil, frameTypeHeaders)
	out = appendVarint(out, maxHeadersPayload)
	return append(out, make([]byte, size)...)
}

func measuredTotal(a *Assembler) int {
	total := 0
	for _, cs := range a.conns {
		total += cs.measure()
	}
	return total
}

func TestPartialFramesOnManyConnectionsStayWithinTheBudget(t *testing.T) {
	a := NewAssembler(nil)
	chunk := partialHeaders(8000)
	for conn := uint64(0); conn < maxConnections; conn++ {
		for stream := uint64(0); stream < 16; stream++ {
			feed(a, conn, stream*4, 0, chunk)
		}
	}
	if a.retained > maxRetainedBytes {
		t.Fatalf("retained %d bytes, budget %d", a.retained, maxRetainedBytes)
	}
	if got := measuredTotal(a); got != a.retained {
		t.Fatalf("accounted %d bytes, connections hold %d", a.retained, got)
	}
	s := a.Stats()
	if s.BudgetSheds == 0 || s.RetainedBytes != a.retained {
		t.Fatalf("stats = %+v, retained = %d", s, a.retained)
	}
}

func TestTheBudgetDropsTheConnectionHoldingTheMost(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	a.maxRetained = 64 << 10
	feed(a, 0x1, 0, 0, frame(frameTypeHeaders, requestSection(t)))

	for stream := uint64(0); stream < 11; stream++ {
		feed(a, 0x2, stream*4, 0, partialHeaders(6000))
	}
	if _, ok := a.conns[ConnKey{TGID: 42, Conn: 0x2}]; ok {
		t.Fatal("the connection pinning partial frames survived the budget")
	}
	if _, ok := a.conns[ConnKey{TGID: 42, Conn: 0x1}]; !ok {
		t.Fatal("a connection that was only decoding was dropped")
	}
	if a.Stats().BudgetSheds != 1 {
		t.Fatalf("sheds = %d, want 1", a.Stats().BudgetSheds)
	}

	feed(a, 0x1, 4, 0, frame(frameTypeHeaders, requestSection(t)))
	if len(c.sections) != 2 {
		t.Fatalf("sections = %d; the surviving connection stopped decoding", len(c.sections))
	}
}

func TestRetainedBytesReturnToZeroWhenConnectionsGo(t *testing.T) {
	now := time.Unix(0, 0)
	a := NewAssembler(nil)
	a.now = func() time.Time { return now }
	feed(a, 0x1, 0, 0, partialHeaders(3000))
	feed(a, 0x2, 0, 0, partialHeaders(3000))
	feed(a, 0x3, 0, 0, partialHeaders(3000))
	if a.retained < 9000 {
		t.Fatalf("retained = %d for three partial frames", a.retained)
	}

	a.Feed(Chunk{TGID: 42, Conn: 0x1, Flags: ChunkFlagConnClosed})
	if got := measuredTotal(a); got != a.retained {
		t.Fatalf("after close: accounted %d, held %d", a.retained, got)
	}
	now = now.Add(connIdleTTL + sweepInterval + time.Second)
	feed(a, 0x4, 0, 0, frame(frameTypeHeaders, requestSection(t)))
	a.Feed(Chunk{TGID: 42, Conn: 0x4, Flags: ChunkFlagConnClosed})
	if a.retained != 0 || a.Stats().RetainedBytes != 0 {
		t.Fatalf("retained = %d (published %d) with no connections", a.retained, a.Stats().RetainedBytes)
	}
}

func TestAPartialFrameHoldsOnlyItsOwnBytes(t *testing.T) {
	a := NewAssembler(nil)
	complete := frame(frameTypeHeaders, requestSection(t))
	data := append(append([]byte{}, complete...), partialHeaders(100)...)
	feed(a, 0x1, 0, 0, data)
	st := a.conns[ConnKey{TGID: 42, Conn: 0x1}].streams[0]
	if len(st.buf) == 0 || cap(st.buf) != len(st.buf) {
		t.Fatalf("partial frame len %d cap %d", len(st.buf), cap(st.buf))
	}
}
