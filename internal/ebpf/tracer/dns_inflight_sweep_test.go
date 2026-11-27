package tracer

import (
	"context"
	"errors"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/events"
)

type inflightEntry struct {
	key dnsFlowKey
	val dnsQueryState
}

type fakeInflightIter struct {
	entries []inflightEntry
	err     error
	next    int
}

func (f *fakeInflightIter) Next(key, value any) bool {
	if f.next >= len(f.entries) {
		return false
	}
	e := f.entries[f.next]
	f.next++
	*key.(*dnsFlowKey) = e.key
	*value.(*dnsQueryState) = e.val
	return true
}

func (f *fakeInflightIter) Err() error { return f.err }

type fakeCountIter struct {
	cgroups []uint64
	err     error
	next    int
}

func (f *fakeCountIter) Next(key, value any) bool {
	if f.next >= len(f.cgroups) {
		return false
	}
	*key.(*uint64) = f.cgroups[f.next]
	*value.(*int32) = 1
	f.next++
	return true
}

func (f *fakeCountIter) Err() error { return f.err }

type fakeInflightDeleter struct {
	deleted []dnsFlowKey
	fail    map[uint64]bool
}

func (f *fakeInflightDeleter) Delete(key any) error {
	k := *key.(*dnsFlowKey)
	if f.fail[k.CgroupID] {
		return errors.New("delete failed")
	}
	f.deleted = append(f.deleted, k)
	return nil
}

const sweepNow = uint64(100 * dnsTimeoutThresholdNS)

func staleQuery(cgroup uint64, txid uint32) inflightEntry {
	return inflightEntry{
		key: dnsFlowKey{CgroupID: cgroup, Txid: txid},
		val: dnsQueryState{TsNS: 1, LastNS: 1},
	}
}

func freshQuery(cgroup uint64, txid uint32) inflightEntry {
	return inflightEntry{
		key: dnsFlowKey{CgroupID: cgroup, Txid: txid},
		val: dnsQueryState{TsNS: sweepNow - 1, LastNS: sweepNow - 1},
	}
}

func sweepTracer(allowed ...uint64) *Tracer {
	tr := newAttributionTestTracer()
	tr.filter = filter.NewCgroupFilter()
	ids := map[uint64]struct{}{}
	for _, id := range allowed {
		ids[id] = struct{}{}
	}
	tr.storeCgroupIDs(ids)
	return tr
}

func TestTheSweepTimesOutStaleQueriesAndCountsTheRestPerCgroup(t *testing.T) {
	tr := sweepTracer(1, 2)
	iter := &fakeInflightIter{entries: []inflightEntry{
		staleQuery(1, 1), freshQuery(1, 2), freshQuery(1, 3),
		staleQuery(2, 4),
		{key: dnsFlowKey{CgroupID: 3, Txid: 5}, val: dnsQueryState{}},
		staleQuery(4, 6),
	}}
	m := &fakeInflightDeleter{}
	ch := make(chan *events.Event, 8)

	live, complete := tr.sweepDNSInflight(context.Background(), ch, iter, m, sweepNow)
	if !complete {
		t.Fatal("a full walk reported itself incomplete")
	}
	want := map[uint64]int32{1: 2, 2: 0, 3: 1, 4: 0}
	for cgroup, count := range want {
		if live[cgroup] != count {
			t.Errorf("cgroup %d has %d in flight, want %d", cgroup, live[cgroup], count)
		}
	}
	if len(m.deleted) != 3 {
		t.Errorf("deleted %v, want the three stale queries", m.deleted)
	}
	close(ch)
	var timedOut []uint64
	for ev := range ch {
		if ev.Error != events.DNSErrorTimeout {
			t.Errorf("event %+v is not a timeout", ev)
		}
		timedOut = append(timedOut, ev.CgroupID)
	}
	if len(timedOut) != 2 {
		t.Errorf("timeouts for cgroups %v, want 1 and 2 only: cgroup 4 is not traced", timedOut)
	}
}

func TestAStaleQueryThatCannotBeDeletedStaysCounted(t *testing.T) {
	tr := sweepTracer(7)
	iter := &fakeInflightIter{entries: []inflightEntry{staleQuery(7, 1)}}
	m := &fakeInflightDeleter{fail: map[uint64]bool{7: true}}

	live, complete := tr.sweepDNSInflight(context.Background(), make(chan *events.Event, 1), iter, m, sweepNow)
	if !complete || live[7] != 1 {
		t.Errorf("live=%v complete=%v; a query still in the map must stay counted", live, complete)
	}
}

func TestAFailedWalkDoesNotReplaceTheCounts(t *testing.T) {
	tr := sweepTracer(1)
	iter := &fakeInflightIter{entries: []inflightEntry{staleQuery(1, 1)}, err: errors.New("iteration aborted")}
	m := &fakeInflightDeleter{}

	if _, complete := tr.sweepDNSInflight(context.Background(), make(chan *events.Event, 1), iter, m, sweepNow); complete {
		t.Error("a walk the iterator aborted reported itself complete, so its partial counts would overwrite the probes'")
	}
	if len(m.deleted) != 1 {
		t.Errorf("deleted %v; the stale query it did see must still be removed", m.deleted)
	}
}

func TestACancelledSweepStopsWithoutCounting(t *testing.T) {
	tr := sweepTracer(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	iter := &fakeInflightIter{entries: []inflightEntry{staleQuery(1, 1), staleQuery(1, 2)}}
	m := &fakeInflightDeleter{}

	live, complete := tr.sweepDNSInflight(ctx, make(chan *events.Event), iter, m, sweepNow)
	if complete || live != nil || len(m.deleted) != 0 {
		t.Errorf("live=%v complete=%v deleted=%v; a cancelled sweep must stop at once", live, complete, m.deleted)
	}
}

func TestTheCountSyncRemovesCgroupsWithNothingInFlight(t *testing.T) {
	m := &fakeInflightCounts{counts: map[uint64]int32{1: 5, 2: 3}}
	syncDNSInflightCountsFrom(&fakeCountIter{cgroups: []uint64{1, 2}}, m, map[uint64]int32{1: 2})
	if len(m.counts) != 1 || m.counts[1] != 2 {
		t.Errorf("counts %v, want only cgroup 1 with 2", m.counts)
	}
}

func TestAFailedCountWalkWritesNothing(t *testing.T) {
	m := &fakeInflightCounts{counts: map[uint64]int32{1: 5, 2: 3}}
	syncDNSInflightCountsFrom(&fakeCountIter{cgroups: []uint64{1}, err: errors.New("iteration aborted")}, m, map[uint64]int32{1: 2})
	if len(m.counts) != 2 || m.counts[1] != 5 || m.counts[2] != 3 {
		t.Errorf("counts %v; a failed walk must leave the counts as they were", m.counts)
	}
}
