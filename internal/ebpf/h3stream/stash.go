package h3stream

import (
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/ebpf/h3decode"
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
}

// SectionStash hands decoded inbound sections from the chunk reader
// goroutine to the transaction reader goroutine.
type SectionStash struct {
	mu       sync.Mutex
	entries  map[SectionKey]stashEntry
	ttl      time.Duration
	capacity int
}

// NewSectionStash returns a stash holding at most capacity sections for at
// most ttl each.
func NewSectionStash(ttl time.Duration, capacity int) *SectionStash {
	return &SectionStash{
		entries:  make(map[SectionKey]stashEntry),
		ttl:      ttl,
		capacity: capacity,
	}
}

// Put stores a section; sections carrying neither pseudo-headers nor a
// traceparent (trailer blocks) are not worth holding.
func (s *SectionStash) Put(key SectionKey, sec Section) {
	if sec.Method == "" && sec.Status == 0 && sec.Traceparent == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= s.capacity {
		for k, e := range s.entries {
			if now.After(e.expires) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= s.capacity {
			return
		}
	}
	s.entries[key] = stashEntry{section: sec, expires: now.Add(s.ttl)}
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
	if time.Now().After(e.expires) {
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
