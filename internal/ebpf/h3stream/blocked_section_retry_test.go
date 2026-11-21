package h3stream

import "testing"

func TestBlockedSectionStaysParkedUntilEveryInsertArrives(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x5000
	key := ConnKey{TGID: 42, Conn: conn}

	feed(a, conn, 3, 0, append([]byte{0x00}, frame(0x4, mustHex(t, "01 40dc"))...))
	feed(a, conn, 0, 0, frame(frameTypeHeaders, mustHex(t, "0300 81 80")))
	if len(c.sections) != 0 || len(a.conns[key].blocked) != 1 {
		t.Fatalf("sections %d blocked %d, want the section parked", len(c.sections), len(a.conns[key].blocked))
	}

	feed(a, conn, 7, 0, append([]byte{0x02}, mustHex(t, "3fbd01 4161 0176")...))
	if len(c.sections) != 0 || len(a.conns[key].blocked) != 1 {
		t.Fatalf("sections %d blocked %d after one of two inserts", len(c.sections), len(a.conns[key].blocked))
	}

	feed(a, conn, 7, 8, mustHex(t, "4162 0177"))
	if len(c.sections) != 1 || len(a.conns[key].blocked) != 0 {
		t.Fatalf("sections %d blocked %d after both inserts", len(c.sections), len(a.conns[key].blocked))
	}
	if c.sections[0].StreamID != 0 {
		t.Fatalf("section = %+v", c.sections[0])
	}
}
