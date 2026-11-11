package analyzer

import (
	"reflect"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func fsEvent(t events.EventType, cgroup uint64, latencyMs float64, bytes uint64) *events.Event {
	return &events.Event{Type: t, CgroupID: cgroup, LatencyNS: uint64(latencyMs * float64(config.NSPerMS)), Bytes: bytes}
}

func totalsOf(evs []*events.Event, threshold float64) FSEventTotals {
	t := FSEventTotals{}
	for _, e := range evs {
		t.Add(e, threshold)
	}
	return t
}

func TestASampledBufferIsWeighedAgainstTheKernelsCompleteFastCounts(t *testing.T) {
	var all []*events.Event
	for i := 0; i < 10_000; i++ {
		all = append(all, fsEvent(events.EventWrite, 7, 50, 4096))
	}
	totals := totalsOf(all, 10)
	kept := all[:100]
	kernel := FSKernelCounts{events.EventWrite: {Count: 90_000, SumNS: 90_000 * 500_000, Buckets: map[float64]uint64{0.5: 90_000}}}

	st := AnalyzeFSSampled(kept, totals, kernel, 10)

	if st.Writes != 100_000 || st.KernelCounted != 90_000 {
		t.Errorf("writes=%d kernel=%d, want 100000 of which 90000 counted in the kernel", st.Writes, st.KernelCounted)
	}
	if st.SlowOps != 10_000 {
		t.Errorf("slow operations = %d, want all 10000", st.SlowOps)
	}
	if st.P50 != 0.5 || st.P95 != 50 || st.P99 != 50 {
		t.Errorf("p50/p95/p99 = %v/%v/%v, want 0.5/50/50 with one write in ten slow", st.P50, st.P95, st.P99)
	}
	if want := (10_000*50.0 + 90_000*0.5) / 100_000; st.AvgMs < want-0.001 || st.AvgMs > want+0.001 {
		t.Errorf("avg = %v, want %v", st.AvgMs, want)
	}
	if st.TotalBytes != 10_000*4096 || st.MaxMs != 50 {
		t.Errorf("bytes=%d max=%v, want every write's bytes and a 50ms max", st.TotalBytes, st.MaxMs)
	}

	unweighted := AnalyzeFSWithKernelCounts(kept, kernel, 10)
	if unweighted.P95 != 0.5 || unweighted.SlowOps != 100 {
		t.Fatalf("without totals p95=%v slow=%d; the fixture no longer shows the under-count", unweighted.P95, unweighted.SlowOps)
	}
}

func TestAnUnsampledBufferGivesTheSameStatsWithOrWithoutTotals(t *testing.T) {
	evs := []*events.Event{
		fsEvent(events.EventWrite, 1, 2, 100),
		fsEvent(events.EventRead, 1, 30, 200),
		fsEvent(events.EventFsync, 2, 12, 0),
		fsEvent(events.EventRead, 2, 1.5, 1<<62),
	}
	kernel := FSKernelCounts{events.EventRead: {Count: 5, SumNS: 2_000_000, Bytes: 50, Buckets: map[float64]uint64{0.25: 3, 1: 2}}}
	without := AnalyzeFSWithKernelCounts(evs, kernel, 10)
	with := AnalyzeFSSampled(evs, totalsOf(evs, 10), kernel, 10)
	if !reflect.DeepEqual(without, with) {
		t.Errorf("stats differ:\nwithout %+v\nwith    %+v", without, with)
	}
}

func TestAKeyWhoseEventsWereAllEvictedStillCounts(t *testing.T) {
	totals := FSEventTotals{
		{CgroupID: 3, Type: events.EventFsync}: {Count: 4, SumNS: 4 * 20_000_000, MaxNS: 30_000_000, SlowOps: 4},
	}
	st := AnalyzeFSSampled([]*events.Event{fsEvent(events.EventWrite, 3, 1, 0)}, totals, nil, 10)
	if st.Fsyncs != 4 || st.Writes != 1 || st.SlowOps != 4 || st.MaxMs != 30 {
		t.Errorf("stats = %+v, want 4 fsyncs from totals and the buffered write", st)
	}
	if st.P99 != 20 {
		t.Errorf("p99 = %v, want the evicted fsyncs at their 20ms mean", st.P99)
	}
}

func TestTotalsShorterThanTheBufferAreIgnoredForThatKey(t *testing.T) {
	evs := []*events.Event{fsEvent(events.EventRead, 1, 20, 0), fsEvent(events.EventRead, 1, 20, 0)}
	totals := FSEventTotals{{CgroupID: 1, Type: events.EventRead}: {Count: 1, SumNS: 1}}
	st := AnalyzeFSSampled(evs, totals, nil, 10)
	if st.Reads != 2 || st.SlowOps != 2 {
		t.Errorf("stats = %+v, want the two buffered reads", st)
	}
}

func TestAddCountsOnlyFilesystemEvents(t *testing.T) {
	tot := FSEventTotals{}
	tot.Add(nil, 10)
	tot.Add(&events.Event{Type: events.EventTCPSend, LatencyNS: 1}, 10)
	tot.Add(fsEvent(events.EventWrite, 9, 5, 1<<62), 10)
	tot.Add(fsEvent(events.EventWrite, 9, 15, 10), 10)
	got := tot[FSEventKey{CgroupID: 9, Type: events.EventWrite}]
	if len(tot) != 1 || got.Count != 2 || got.SlowOps != 1 || got.Bytes != 10 || got.MaxNS != 15_000_000 || got.SumNS != 20_000_000 {
		t.Errorf("totals = %+v", tot)
	}
}

func TestAPodsShareOfTheTotalsFollowsItsShareOfTheBuffer(t *testing.T) {
	whole := FSEventKey{CgroupID: 1, Type: events.EventWrite}
	split := FSEventKey{CgroupID: 2, Type: events.EventRead}
	untotalled := FSEventKey{CgroupID: 3, Type: events.EventRead}
	totals := FSEventTotals{
		whole:                                  {Count: 400, SumNS: 4000, MaxNS: 90, SlowOps: 40, Bytes: 800},
		split:                                  {Count: 1000, SumNS: 10_000, MaxNS: 99, SlowOps: 100, Bytes: 2000},
		{CgroupID: 4, Type: events.EventFsync}: {Count: 5},
	}
	podEvents := []*events.Event{
		{Type: events.EventWrite, CgroupID: 1, LatencyNS: 10},
		{Type: events.EventWrite, CgroupID: 1, LatencyNS: 20},
		{Type: events.EventRead, CgroupID: 2, LatencyNS: 7},
		{Type: events.EventRead, CgroupID: 3, LatencyNS: 7},
		{Type: events.EventTCPSend, CgroupID: 1},
		nil,
	}
	keptOverall := map[FSEventKey]uint64{whole: 2, split: 4, untotalled: 1}

	got := totals.Share(podEvents, keptOverall)

	if !reflect.DeepEqual(got[whole], totals[whole]) {
		t.Errorf("whole key = %+v, want the full total", got[whole])
	}
	if want := (FSEventTotal{Count: 250, SumNS: 2500, MaxNS: 7, SlowOps: 25, Bytes: 500}); got[split] != want {
		t.Errorf("split key = %+v, want %+v", got[split], want)
	}
	if len(got) != 2 {
		t.Errorf("share = %+v, want only the two totalled keys this pod holds", got)
	}
	if got := totals.Share(podEvents, map[FSEventKey]uint64{}); len(got) != 0 {
		t.Errorf("share with no kept counts = %+v, want nothing", got)
	}
	if got := (FSEventTotals{split: {Count: 2}}).Share(podEvents, map[FSEventKey]uint64{split: 3}); got[split].Count != 1 {
		t.Errorf("share count = %d, want at least the pod's one kept event", got[split].Count)
	}
}
