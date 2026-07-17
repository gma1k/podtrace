// Package attribution maintains a short-lived map from host PID to the
// process identity (comm, cgroup) most recently captured in kernel
// context, so events produced by BPF program types that cannot call
// bpf_get_current_comm — the cgroup_skb DNS and QUIC probes, can be
// attributed at ingest while the owning process is still alive, instead
// of through a deferred /proc lookup that races process exit and pid
// recycling.
package attribution

import (
	"container/list"
	"sync"
	"time"
)

// DefaultTTL bounds how long a captured identity may attribute later
// events.
const DefaultTTL = 30 * time.Second

// DefaultMaxEntries caps the table..
const DefaultMaxEntries = 8192

type entry struct {
	pid      uint32
	comm     string
	cgroupID uint64
	seenAt   time.Time
}

// Table is a concurrency-safe pid, identity map with TTL expiry and
// LRU eviction.
type Table struct {
	mu         sync.Mutex
	entries    map[uint32]*list.Element
	order      *list.List
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
}

// New returns an empty table.
func New(ttl time.Duration, maxEntries int) *Table {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Table{
		entries:    make(map[uint32]*list.Element, 256),
		order:      list.New(),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Record stores (comm, cgroupID) as the identity of pid, replacing any
// previous identity (last-writer-wins: on pid reuse the newest owner is
// the correct one).
func (t *Table) Record(pid uint32, cgroupID uint64, comm string) {
	if t == nil || pid == 0 || comm == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if el, ok := t.entries[pid]; ok {
		e := el.Value.(*entry)
		e.comm = comm
		e.cgroupID = cgroupID
		e.seenAt = now
		t.order.MoveToFront(el)
		return
	}
	if t.order.Len() >= t.maxEntries {
		oldest := t.order.Back()
		if oldest != nil {
			t.order.Remove(oldest)
			delete(t.entries, oldest.Value.(*entry).pid)
		}
	}
	t.entries[pid] = t.order.PushFront(&entry{
		pid:      pid,
		comm:     comm,
		cgroupID: cgroupID,
		seenAt:   now,
	})
}

// Lookup returns the comm recorded for pid, if it is still within TTL
// and its cgroup is consistent with the event being attributed.
func (t *Table) Lookup(pid uint32, cgroupID uint64) (comm string, ok bool, reuseSuspected bool) {
	if t == nil || pid == 0 {
		return "", false, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	el, found := t.entries[pid]
	if !found {
		return "", false, false
	}
	e := el.Value.(*entry)
	if t.now().Sub(e.seenAt) > t.ttl {
		t.order.Remove(el)
		delete(t.entries, pid)
		return "", false, false
	}
	if cgroupID != 0 && e.cgroupID != 0 && e.cgroupID != cgroupID {
		t.order.Remove(el)
		delete(t.entries, pid)
		return "", false, true
	}
	return e.comm, true, false
}

// Len returns the number of live entries.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.order.Len()
}