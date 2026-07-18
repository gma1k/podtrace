package attribution

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type fixedClock struct {
	mu  sync.Mutex
	t   time.Time
}

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestTable(ttl time.Duration, maxEntries int) (*Table, *fixedClock) {
	clock := &fixedClock{t: time.Unix(1_000_000, 0)}
	table := New(ttl, maxEntries)
	table.now = clock.now
	return table, clock
}

func TestRecordAndLookupHit(t *testing.T) {
	table, _ := newTestTable(time.Minute, 16)
	table.Record(42, 100, "nslookup")

	comm, ok, reuse := table.Lookup(42, 100)
	if !ok || reuse {
		t.Fatalf("Lookup(42,100) = (%q,%v,%v), want hit without reuse", comm, ok, reuse)
	}
	if comm != "nslookup" {
		t.Fatalf("comm = %q, want nslookup", comm)
	}
}

func TestLookupMiss(t *testing.T) {
	table, _ := newTestTable(time.Minute, 16)
	if _, ok, reuse := table.Lookup(7, 100); ok || reuse {
		t.Fatalf("Lookup on empty table = hit=%v reuse=%v, want miss", ok, reuse)
	}
}

func TestTTLEviction(t *testing.T) {
	table, clock := newTestTable(10*time.Second, 16)
	table.Record(42, 100, "curl")

	clock.advance(9 * time.Second)
	if _, ok, _ := table.Lookup(42, 100); !ok {
		t.Fatal("entry expired before TTL")
	}

	clock.advance(2 * time.Second)
	if _, ok, _ := table.Lookup(42, 100); ok {
		t.Fatal("entry survived past TTL")
	}
	if table.Len() != 0 {
		t.Fatalf("expired entry not evicted, Len = %d", table.Len())
	}
}

func TestLastWriterWins(t *testing.T) {
	table, _ := newTestTable(time.Minute, 16)
	table.Record(42, 100, "old-owner")
	table.Record(42, 100, "new-owner")

	comm, ok, _ := table.Lookup(42, 100)
	if !ok || comm != "new-owner" {
		t.Fatalf("Lookup = (%q,%v), want new-owner hit", comm, ok)
	}
	if table.Len() != 1 {
		t.Fatalf("rewrite duplicated the entry, Len = %d", table.Len())
	}
}

func TestCgroupMismatchSuspectsPidReuse(t *testing.T) {
	table, _ := newTestTable(time.Minute, 16)
	table.Record(42, 100, "victim")

	comm, ok, reuse := table.Lookup(42, 200)
	if ok || comm != "" {
		t.Fatalf("cross-cgroup lookup returned %q, want miss", comm)
	}
	if !reuse {
		t.Fatal("cross-cgroup lookup did not flag pid reuse")
	}
	if _, ok, reuse := table.Lookup(42, 200); ok || reuse {
		t.Fatalf("stale entry survived reuse eviction: hit=%v reuse=%v", ok, reuse)
	}
}

// TestZeroCgroupIsUnverifiable is the regression for the pid-reuse guard
// bypass.
func TestZeroCgroupIsUnverifiable(t *testing.T) {
	table, _ := newTestTable(time.Minute, 16)

	table.Record(42, 0, "victim-pod-comm")
	if comm, ok, reuse := table.Lookup(42, 200); ok || reuse || comm != "" {
		t.Fatalf("zero recorded cgroup must be unverifiable (miss), got hit=%v reuse=%v comm=%q", ok, reuse, comm)
	}

	table.Record(43, 100, "curl")
	if comm, ok, reuse := table.Lookup(43, 0); ok || reuse || comm != "" {
		t.Fatalf("zero event cgroup must be unverifiable (miss), got hit=%v reuse=%v comm=%q", ok, reuse, comm)
	}
	if comm, ok, reuse := table.Lookup(43, 100); !ok || reuse || comm != "curl" {
		t.Fatalf("unverifiable lookup must not evict the entry; want curl hit, got hit=%v reuse=%v comm=%q", ok, reuse, comm)
	}
}

func TestLRUCapEviction(t *testing.T) {
	const cap = 8
	table, _ := newTestTable(time.Minute, cap)
	for pid := uint32(1); pid <= cap+3; pid++ {
		table.Record(pid, 100, fmt.Sprintf("proc-%d", pid))
	}
	if table.Len() != cap {
		t.Fatalf("Len = %d, want %d", table.Len(), cap)
	}
	for pid := uint32(1); pid <= 3; pid++ {
		if _, ok, _ := table.Lookup(pid, 100); ok {
			t.Fatalf("pid %d survived cap eviction", pid)
		}
	}
	if _, ok, _ := table.Lookup(cap+3, 100); !ok {
		t.Fatal("most recent entry missing after cap eviction")
	}
}

func TestRewriteRefreshesLRUPosition(t *testing.T) {
	table, _ := newTestTable(time.Minute, 2)
	table.Record(1, 100, "a")
	table.Record(2, 100, "b")
	table.Record(1, 100, "a2")
	table.Record(3, 100, "c")

	if _, ok, _ := table.Lookup(2, 100); ok {
		t.Fatal("refreshed entry was evicted instead of the stale one")
	}
	if comm, ok, _ := table.Lookup(1, 100); !ok || comm != "a2" {
		t.Fatalf("Lookup(1) = (%q,%v), want a2 hit", comm, ok)
	}
}

func TestIgnoresPidZeroAndEmptyComm(t *testing.T) {
	table, _ := newTestTable(time.Minute, 16)
	table.Record(0, 100, "kernel")
	table.Record(42, 100, "")
	if table.Len() != 0 {
		t.Fatalf("invalid records were stored, Len = %d", table.Len())
	}
	if _, ok, _ := table.Lookup(0, 100); ok {
		t.Fatal("Lookup(0) must miss")
	}
}

func TestNilTableIsSafe(t *testing.T) {
	var table *Table
	table.Record(42, 100, "curl")
	if _, ok, reuse := table.Lookup(42, 100); ok || reuse {
		t.Fatal("nil table must always miss")
	}
	if table.Len() != 0 {
		t.Fatal("nil table Len must be 0")
	}
}

func TestConcurrentAccess(t *testing.T) {
	table, _ := newTestTable(time.Minute, 128)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				pid := uint32(w*1000 + i%64 + 1)
				table.Record(pid, uint64(w+1), "worker")
				table.Lookup(pid, uint64(w+1))
			}
		}(w)
	}
	wg.Wait()
}