package h3stream

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
)

func qpackInteger(first byte, prefixBits uint, v int) []byte {
	limit := 1<<prefixBits - 1
	if v < limit {
		return []byte{first | byte(v)}
	}
	out := []byte{first | byte(limit)}
	v -= limit
	for v >= 0x80 {
		out = append(out, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func qpackStaticNameLiteral(index int, value string) []byte {
	out := qpackInteger(0x50, 4, index)
	out = append(out, qpackInteger(0x00, 7, len(value))...)
	return append(out, value...)
}

func qpackLiteralName(name, value string) []byte {
	out := qpackInteger(0x20, 3, len(name))
	out = append(out, name...)
	out = append(out, qpackInteger(0x00, 7, len(value))...)
	return append(out, value...)
}

func fieldSection(lines ...[]byte) []byte {
	return append([]byte{0x00, 0x00}, bytes.Join(lines, nil)...)
}

func TestSectionStringsAreBounded(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	longPath := "/" + strings.Repeat("p", 3000)
	longMethod := strings.Repeat("M", 40)
	longTraceparent := "00-" + strings.Repeat("a", 80)

	feed(a, 0x3000, 0, 0, frame(frameTypeHeaders, fieldSection(
		qpackStaticNameLiteral(15, longMethod),
		qpackStaticNameLiteral(1, longPath),
		qpackLiteralName("traceparent", longTraceparent),
	)))

	if len(c.sections) != 1 {
		t.Fatalf("got %d sections, want 1", len(c.sections))
	}
	sec := c.sections[0]
	if len(sec.Path) != sectionPathMax || !strings.HasSuffix(sec.Path, "...") || !strings.HasPrefix(sec.Path, "/ppp") {
		t.Fatalf("path not bounded: len %d", len(sec.Path))
	}
	if len(sec.Method) != sectionMethodMax {
		t.Fatalf("method not bounded: %q", sec.Method)
	}
	if sec.Traceparent != "" {
		t.Fatalf("oversized traceparent kept: %q", sec.Traceparent)
	}
}

func TestSectionKeepsValuesWithinBounds(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	feed(a, 0x3100, 0, 0, frame(frameTypeHeaders, fieldSection(
		[]byte{0xd1},
		qpackStaticNameLiteral(1, "/orders/42"),
		qpackLiteralName("traceparent", traceparent),
	)))

	if len(c.sections) != 1 {
		t.Fatalf("got %d sections, want 1", len(c.sections))
	}
	sec := c.sections[0]
	if sec.Method != "GET" || sec.Path != "/orders/42" || sec.Traceparent != traceparent {
		t.Fatalf("section = %+v", sec)
	}
}

func TestSectionWithTooManyFieldLinesIsDropped(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	flood := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0xd1}, 4080)...)
	feed(a, 0x3200, 0, 0, frame(frameTypeHeaders, flood))
	if len(c.sections) != 0 {
		t.Fatalf("flooded section emitted: %d", len(c.sections))
	}

	fits := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0xd1}, 256)...)
	feed(a, 0x3200, 4, 0, frame(frameTypeHeaders, fits))
	if len(c.sections) != 1 || c.sections[0].Method != "GET" {
		t.Fatalf("section at the field cap not emitted: %+v", c.sections)
	}
}

type stashClock struct{ now time.Time }

func (c *stashClock) read() time.Time { return c.now }

func newClockedStash(ttl time.Duration, capacity int) (*SectionStash, *stashClock) {
	clock := &stashClock{now: time.Unix(1_700_000_000, 0)}
	s := NewSectionStash(ttl, capacity)
	s.now = clock.read
	return s, clock
}

func TestStashPutExpiresOldEntriesBeforeFillingUp(t *testing.T) {
	s, clock := newClockedStash(time.Second, 4)
	for i := uint64(0); i < 4; i++ {
		s.Put(SectionKey{Stream: i}, Section{Status: 200})
	}
	clock.now = clock.now.Add(2 * time.Second)

	s.Put(SectionKey{Stream: 99}, Section{Status: 204})

	if s.Dropped() != 0 {
		t.Fatalf("dropped %d with every old entry expired", s.Dropped())
	}
	if len(s.entries) != 1 {
		t.Fatalf("stash holds %d entries, want only the fresh one", len(s.entries))
	}
	if sec, ok := s.Take(SectionKey{Stream: 99}); !ok || sec.Status != 204 {
		t.Fatalf("take = %+v %v", sec, ok)
	}
}

func TestStashDropsWhenFullOfFreshEntries(t *testing.T) {
	s, _ := newClockedStash(time.Second, 2)
	s.Put(SectionKey{Stream: 1}, Section{Status: 200})
	s.Put(SectionKey{Stream: 2}, Section{Status: 200})
	s.Put(SectionKey{Stream: 3}, Section{Status: 200})

	if s.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", s.Dropped())
	}
	if _, ok := s.Take(SectionKey{Stream: 3}); ok {
		t.Fatal("section stored beyond capacity")
	}
}

func TestStashFullStashStillReplacesAnExistingKey(t *testing.T) {
	s, _ := newClockedStash(time.Second, 2)
	s.Put(SectionKey{Stream: 1}, Section{Status: 200})
	s.Put(SectionKey{Stream: 2}, Section{Status: 200})
	s.Put(SectionKey{Stream: 1}, Section{Status: 503})

	if s.Dropped() != 0 {
		t.Fatalf("dropped = %d replacing an existing key", s.Dropped())
	}
	if sec, ok := s.Take(SectionKey{Stream: 1}); !ok || sec.Status != 503 {
		t.Fatalf("take = %+v %v", sec, ok)
	}
}

func TestStashReplacedEntryIsNotExpiredByItsOldRef(t *testing.T) {
	s, clock := newClockedStash(time.Second, 4)
	key := SectionKey{Stream: 1}
	s.Put(key, Section{Status: 200})
	clock.now = clock.now.Add(800 * time.Millisecond)
	s.Put(key, Section{Status: 404})
	clock.now = clock.now.Add(400 * time.Millisecond)

	s.Put(SectionKey{Stream: 2}, Section{Status: 200})

	if sec, ok := s.Take(key); !ok || sec.Status != 404 {
		t.Fatalf("replaced entry lost to its stale ref: %+v %v", sec, ok)
	}
}

func TestStashTakeOfExpiredEntryMisses(t *testing.T) {
	s, clock := newClockedStash(time.Second, 4)
	s.Put(SectionKey{Stream: 1}, Section{Status: 200})
	clock.now = clock.now.Add(2 * time.Second)

	if _, ok := s.Take(SectionKey{Stream: 1}); ok {
		t.Fatal("expired section returned")
	}
}

func TestStashOrderQueueStaysBoundedUnderTakeChurn(t *testing.T) {
	s, _ := newClockedStash(time.Hour, 8)
	for i := uint64(0); i < 10_000; i++ {
		key := SectionKey{Stream: i}
		s.Put(key, Section{Status: 200})
		if _, ok := s.Take(key); !ok {
			t.Fatalf("take %d missed", i)
		}
	}
	if pending := len(s.order) - s.head; pending > 2*s.capacity+1 {
		t.Fatalf("order queue holds %d refs for capacity %d", pending, s.capacity)
	}
}

func TestStashOrderQueueReleasesExpiredRefs(t *testing.T) {
	s, clock := newClockedStash(time.Second, 64)
	for i := uint64(0); i < 64; i++ {
		s.Put(SectionKey{Stream: i}, Section{Status: 200})
	}
	clock.now = clock.now.Add(2 * time.Second)

	s.Put(SectionKey{Stream: 1000}, Section{Status: 200})

	if len(s.order) != 1 || s.head != 0 {
		t.Fatalf("order len %d head %d after every old ref expired", len(s.order), s.head)
	}
}

func TestEnrichTxnFromBoundedSection(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	s := NewSectionStash(time.Minute, 16)
	feed(a, 0x3300, 8, 0, frame(frameTypeHeaders, fieldSection(
		[]byte{0xd1},
		qpackStaticNameLiteral(1, "/"+strings.Repeat("q", 5000)),
	)))
	for i, sec := range c.sections {
		s.Put(SectionKey{TGID: c.keys[i].TGID, Conn: c.keys[i].Conn, Stream: sec.StreamID}, sec)
	}

	sec, ok := s.Take(SectionKey{TGID: 42, Conn: 0x3300, Stream: 8})
	if !ok {
		t.Fatal("section not stashed")
	}
	txn := &h3decode.Txn{Flags: h3decode.FlagResponseOnly}
	if !EnrichTxn(txn, sec) || txn.Method != "GET" || len(txn.Path) != sectionPathMax {
		t.Fatalf("txn = %+v", txn)
	}
}

func TestStashOrderQueueDropsStaleRefsBehindALiveEntry(t *testing.T) {
	s, _ := newClockedStash(time.Hour, 8)
	pinned := SectionKey{Stream: 1 << 40}
	s.Put(pinned, Section{Status: 200})
	for i := uint64(0); i < 1000; i++ {
		key := SectionKey{Stream: i}
		s.Put(key, Section{Status: 200})
		s.Take(key)
	}
	if pending := len(s.order) - s.head; pending > 2*s.capacity+1 {
		t.Fatalf("order queue holds %d refs for capacity %d", pending, s.capacity)
	}
	if sec, ok := s.Take(pinned); !ok || sec.Status != 200 {
		t.Fatalf("live entry lost in compaction: %+v %v", sec, ok)
	}
}
