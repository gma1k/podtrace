package h3stream

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
)

// SectionKey identifies the stream a decoded section belongs to.
type SectionKey struct {
	TGID   uint32
	Conn   uint64
	Stream uint64
}

type stashEntry struct {
	section Section
	expires time.Time
	seq     uint64
}

// stashRef records one Put in arrival order. Every entry lives for the same
// ttl, so arrival order is expiry order.
type stashRef struct {
	key SectionKey
	seq uint64
}

// SectionStash hands decoded inbound sections from the chunk reader
// goroutine to the transaction reader goroutine.
type SectionStash struct {
	mu       sync.Mutex
	entries  map[SectionKey]stashEntry
	order    []stashRef
	head     int
	nextSeq  uint64
	ttl      time.Duration
	capacity int
	now      func() time.Time
	dropped  atomic.Uint64
}

// NewSectionStash returns a stash holding at most capacity sections for at
// most ttl each.
func NewSectionStash(ttl time.Duration, capacity int) *SectionStash {
	return &SectionStash{
		entries:  make(map[SectionKey]stashEntry),
		ttl:      ttl,
		capacity: capacity,
		now:      time.Now,
	}
}

// Put stores a section; sections carrying neither pseudo-headers nor a
// traceparent (trailer blocks) are not worth holding.
func (s *SectionStash) Put(key SectionKey, sec Section) {
	if sec.Method == "" && sec.Status == 0 && sec.Traceparent == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	if _, replacing := s.entries[key]; !replacing && len(s.entries) >= s.capacity {
		s.dropped.Add(1)
		return
	}
	s.nextSeq++
	s.entries[key] = stashEntry{section: sec, expires: now.Add(s.ttl), seq: s.nextSeq}
	s.order = append(s.order, stashRef{key: key, seq: s.nextSeq})
	s.compactLocked()
}

// expireLocked removes the entries whose ttl has passed, oldest first, and
// stops at the first live one: Put costs amortised O(1) however full the
// stash is.
func (s *SectionStash) expireLocked(now time.Time) {
	for s.head < len(s.order) {
		ref := s.order[s.head]
		if e, ok := s.entries[ref.key]; ok && e.seq == ref.seq {
			if !now.After(e.expires) {
				return
			}
			delete(s.entries, ref.key)
		}
		s.order[s.head] = stashRef{}
		s.head++
	}
}

// compactLocked bounds the order queue: consumed refs are dropped once they
// make up half of it, and refs left behind by Take or an overwrite once the
// queue holds more than twice capacity.
func (s *SectionStash) compactLocked() {
	if pending := len(s.order) - s.head; s.head > 0 && s.head >= pending {
		s.order = append(s.order[:0], s.order[s.head:]...)
		clear(s.order[pending:cap(s.order)])
		s.head = 0
	}
	if len(s.order)-s.head <= 2*s.capacity {
		return
	}
	kept := make([]stashRef, 0, len(s.entries))
	for _, ref := range s.order[s.head:] {
		if e, ok := s.entries[ref.key]; ok && e.seq == ref.seq {
			kept = append(kept, ref)
		}
	}
	s.order = kept
	s.head = 0
}

// Dropped reports how many sections Put discarded because the stash was full.
func (s *SectionStash) Dropped() uint64 {
	return s.dropped.Load()
}

// Take removes and returns the section for key, if present and fresh.
func (s *SectionStash) Take(key SectionKey) (Section, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return Section{}, false
	}
	delete(s.entries, key)
	if s.now().After(e.expires) {
		return Section{}, false
	}
	return e.section, true
}

// EnrichTxn fills the gaps in an adapter transaction from the decoded
// inbound section of its stream.
func EnrichTxn(txn *h3decode.Txn, sec Section) bool {
	changed := false
	if txn.Status == 0 && sec.Status != 0 {
		txn.Status = sec.Status
		changed = true
	}
	if txn.Method == "" && sec.Method != "" {
		txn.Method = sec.Method
		changed = true
	}
	if txn.Path == "" && sec.Path != "" {
		txn.Path = sec.Path
		changed = true
	}
	if txn.Traceparent == "" && sec.Traceparent != "" {
		txn.Traceparent = sec.Traceparent
		changed = true
	}
	if changed && txn.Flags&h3decode.FlagResponseOnly != 0 && txn.Method != "" {
		txn.Flags &^= h3decode.FlagResponseOnly
	}
	return changed
}
