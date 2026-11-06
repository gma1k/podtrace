package oncpu

import (
	"errors"
	"testing"
)

func TestLostSamplesAreReportedAsGrowthSinceTheLastDrain(t *testing.T) {
	f := &fakeMaps{lost: map[uint32][]uint64{LostStack: {2, 3}, LostFull: {1, 0}}}
	var seen LostTotals

	first, err := drain(f.io(), &seen)
	if err != nil {
		t.Fatal(err)
	}
	if first.Lost[LostStack] != 5 || first.Lost[LostFull] != 1 {
		t.Fatalf("first drain lost = %v, want 5 and 1", first.Lost)
	}

	f.lost[LostStack] = []uint64{4, 3}
	second, err := drain(f.io(), &seen)
	if err != nil {
		t.Fatal(err)
	}
	if second.Lost[LostStack] != 2 || second.Lost[LostFull] != 0 {
		t.Fatalf("second drain lost = %v, want only the 2 added since the first", second.Lost)
	}
}

func TestLostSamplesAfterTheCountersRestartAreReportedWhole(t *testing.T) {
	f := &fakeMaps{lost: map[uint32][]uint64{LostFull: {3}}}
	seen := LostTotals{LostFull: 10}

	d, err := drain(f.io(), &seen)
	if err != nil {
		t.Fatal(err)
	}
	if d.Lost[LostFull] != 3 || seen[LostFull] != 3 {
		t.Fatalf("lost = %v, seen = %v; a counter below its last total restarted from zero", d.Lost, seen)
	}
}

func TestACountRecordedAgainstAStackTheDrainDeletedIsTakenAsUnresolved(t *testing.T) {
	orphan := Key{CgroupID: 7, PID: 10, StackID: 1}
	f := &fakeMaps{
		counts: []Key{{CgroupID: 7, PID: 10, StackID: 1}},
		values: []uint64{2},
		stacks: map[uint32][]uint64{1: {0x10}},
		raced:  []countRow{{key: orphan, count: 4}, {key: Key{StackID: 8}, count: 9}},
	}

	d, err := drain(f.io(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Samples) != 1 || d.Samples[0].Count != 2 {
		t.Fatalf("samples = %+v, want the one row read before the race", d.Samples)
	}
	if d.Unresolved != 4 {
		t.Fatalf("unresolved = %d, want the 4 samples whose stack was deleted under them", d.Unresolved)
	}
	if f.deletedCounts != 2 {
		t.Fatalf("deleted %d counts, want the drained row and the orphan", f.deletedCounts)
	}
}

func TestACountWhoseStackSlotWasRefilledIsLeftForTheNextDrain(t *testing.T) {
	f := &fakeMaps{
		counts:   []Key{{StackID: 1}},
		values:   []uint64{2},
		stacks:   map[uint32][]uint64{1: {0x10}},
		refilled: map[uint32]struct{}{1: {}},
		raced:    []countRow{{key: Key{StackID: 1}, count: 4}},
	}

	d, err := drain(f.io(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Unresolved != 0 || f.deletedCounts != 1 {
		t.Fatalf("unresolved = %d, deleted %d counts; a refilled slot holds a live stack", d.Unresolved, f.deletedCounts)
	}
}

func TestAFailedOrphanRemovalStopsTheDrain(t *testing.T) {
	boom := errors.New("boom")
	f := &fakeMaps{
		stacks:    map[uint32][]uint64{},
		raced:     []countRow{{key: Key{StackID: 1}, count: 4}},
		liveCalls: 1,
	}
	io := f.io()
	io.takeCount = func(*Key, *uint64) error { return boom }
	if _, err := takeOrphanedCounts(io, map[uint32]struct{}{1: {}}); !errors.Is(err, boom) {
		t.Fatalf("takeOrphanedCounts = %v, want the removal failure", err)
	}
}

func TestAFailedOrphanRemovalFailsTheDrain(t *testing.T) {
	boom := errors.New("boom")
	f := &fakeMaps{
		counts: []Key{{StackID: 1}},
		values: []uint64{2},
		stacks: map[uint32][]uint64{1: {0x10}},
		raced:  []countRow{{key: Key{StackID: 1}, count: 4}},
	}
	io := f.io()
	taken := 0
	io.takeCount = func(*Key, *uint64) error {
		taken++
		if taken > 1 {
			return boom
		}
		return nil
	}
	if _, err := drain(io, nil); !errors.Is(err, boom) {
		t.Fatalf("drain = %v, want the orphan removal failure", err)
	}
}
