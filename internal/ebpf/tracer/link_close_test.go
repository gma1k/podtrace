package tracer

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

type slowLink struct {
	link.Link
	delay    time.Duration
	closes   atomic.Int32
	inFlight *atomic.Int32
	peak     *atomic.Int32
}

func (s *slowLink) Close() error {
	n := s.inFlight.Add(1)
	for {
		p := s.peak.Load()
		if n <= p || s.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(s.delay)
	s.inFlight.Add(-1)
	s.closes.Add(1)
	return nil
}

func slowLinks(n int, delay time.Duration) ([]link.Link, []*slowLink, *atomic.Int32) {
	var inFlight, peak atomic.Int32
	ls := make([]link.Link, n)
	raw := make([]*slowLink, n)
	for i := range ls {
		raw[i] = &slowLink{delay: delay, inFlight: &inFlight, peak: &peak}
		ls[i] = raw[i]
	}
	return ls, raw, &peak
}

func TestClosingManySlowLinksTakesAboutAsLongAsOne(t *testing.T) {
	ls, raw, _ := slowLinks(183, 50*time.Millisecond)

	start := time.Now()
	closeLinks(ls)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("closing 183 links of 50ms each took %v.\n\nEach kprobe or uprobe close "+
			"waits out an SRCU grace period in the kernel. Closed one at a time that was "+
			"about 45 seconds on kind, past the pod's 30-second grace period, so every "+
			"agent was SIGKILLed on shutdown.", elapsed)
	}
	for i, l := range raw {
		if got := l.closes.Load(); got != 1 {
			t.Fatalf("link %d closed %d times, want exactly once", i, got)
		}
	}
}

func TestConcurrentClosesStayWithinTheirBound(t *testing.T) {
	ls, _, peak := slowLinks(40, 10*time.Millisecond)
	closeLinksConcurrently(ls, 4)
	if got := peak.Load(); got > 4 {
		t.Errorf("%d closes ran at once, bound is 4", got)
	}
	if got := peak.Load(); got < 2 {
		t.Errorf("only %d close ran at a time; the links were closed one by one", got)
	}
}

func TestClosingNothingOrNilLinksIsSafe(t *testing.T) {
	closeLinks(nil)
	closeLinksConcurrently([]link.Link{nil, nil}, 0)
	ls, raw, _ := slowLinks(1, 0)
	closeLinksConcurrently(append(ls, nil), 8)
	if raw[0].closes.Load() != 1 {
		t.Error("the one real link among nils was not closed")
	}
}
