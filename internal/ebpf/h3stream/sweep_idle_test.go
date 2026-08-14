package h3stream

import (
	"testing"
	"time"
)

func TestAssembler_SweepIdleEvictsStaleConnections(t *testing.T) {
	a := NewAssembler(func(ConnKey, Section) {})
	base := time.Unix(1000, 0)
	a.conns[ConnKey{TGID: 1}] = &connState{lastSeen: base}
	a.conns[ConnKey{TGID: 2}] = &connState{lastSeen: base.Add(90 * time.Second)}

	a.sweepIdle(base.Add(3 * time.Minute))

	if _, ok := a.conns[ConnKey{TGID: 1}]; ok {
		t.Error("connection idle for 3m (> TTL) must be swept")
	}
	if _, ok := a.conns[ConnKey{TGID: 2}]; !ok {
		t.Error("connection active 90s ago (< TTL) must be kept")
	}
}

func TestAssembler_SweepIdleThrottledToInterval(t *testing.T) {
	a := NewAssembler(func(ConnKey, Section) {})
	base := time.Unix(1000, 0)
	a.sweepIdle(base)
	a.conns[ConnKey{TGID: 1}] = &connState{lastSeen: base.Add(-time.Hour)}

	a.sweepIdle(base.Add(sweepInterval - time.Second))
	if _, ok := a.conns[ConnKey{TGID: 1}]; !ok {
		t.Error("a sweep within sweepInterval must be a no-op")
	}

	a.sweepIdle(base.Add(sweepInterval + time.Second))
	if _, ok := a.conns[ConnKey{TGID: 1}]; ok {
		t.Error("a sweep past sweepInterval must evict the idle connection")
	}
}

func TestAssembler_FeedSweepsViaInjectedClock(t *testing.T) {
	a := NewAssembler(func(ConnKey, Section) {})
	clock := time.Unix(1000, 0)
	a.now = func() time.Time { return clock }

	a.conns[ConnKey{TGID: 9, Conn: 9}] = &connState{
		lastSeen: clock,
		streams:  map[uint64]*streamState{},
	}

	clock = clock.Add(5 * time.Minute)
	a.Feed(Chunk{TGID: 1, Conn: 1, StreamID: 0, StreamLen: 1, CopiedLen: 1, Data: []byte{0x00}})

	if _, ok := a.conns[ConnKey{TGID: 9, Conn: 9}]; ok {
		t.Error("Feed must sweep the stale connection using the injected clock")
	}
	if _, ok := a.conns[ConnKey{TGID: 1, Conn: 1}]; !ok {
		t.Error("Feed must retain the freshly-active connection")
	}
}
