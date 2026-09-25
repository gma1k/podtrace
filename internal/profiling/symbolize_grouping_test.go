package profiling

import (
	"context"
	"fmt"
	"testing"
)

type orderRecorder struct{ pids []uint32 }

func (r *orderRecorder) Resolve(_ context.Context, pid uint32, addr uint64) string {
	r.pids = append(r.pids, pid)
	return fmt.Sprintf("p%d_%x", pid, addr)
}

func interleavedCounts() map[frameAddr]int {
	counts := map[frameAddr]int{}
	for i := 0; i < 12; i++ {
		pid := uint32(1 + i%3)
		counts[frameAddr{pid: pid, addr: uint64(0x1000 + i)}] = 100 - i
	}
	return counts
}

func TestFramesAreResolvedOneProcessAtATime(t *testing.T) {
	r := &orderRecorder{}
	symbolizeHotFrames(context.Background(), interleavedCounts(), r)

	seen := map[uint32]bool{}
	for i, pid := range r.pids {
		if i > 0 && pid != r.pids[i-1] && seen[pid] {
			t.Fatalf("returned to pid %d after leaving it: %v.\n\nRanking interleaves "+
				"every workload's frames, and the symbol cache holds only a couple of "+
				"parsed tables, so resolving in rank order reparses the same large "+
				"executable repeatedly within one snapshot.", pid, r.pids)
		}
		seen[pid] = true
	}
}

func TestGroupingDoesNotChangeTheResult(t *testing.T) {
	counts := interleavedCounts()

	got := symbolizeHotFrames(context.Background(), counts, &orderRecorder{})

	if len(got) == 0 {
		t.Fatal("no frames returned")
	}
	for i := 1; i < len(got); i++ {
		if got[i].Count > got[i-1].Count {
			t.Fatalf("output not ranked by count at %d: %+v", i, got)
		}
	}
	if got[0].Frame != "p1_1000" || got[0].Count != 100 {
		t.Errorf("hottest frame = %+v, want p1_1000 with 100; resolution order must not "+
			"change which frame ranks first", got[0])
	}
}

func TestOnlyTheTopFramesAreResolvedEvenWhenGrouped(t *testing.T) {
	counts := map[frameAddr]int{}
	for i := 0; i < maxSymbolizedFrames*3; i++ {
		counts[frameAddr{pid: uint32(1 + i%5), addr: uint64(i)}] = i + 1
	}
	r := &orderRecorder{}
	symbolizeHotFrames(context.Background(), counts, r)

	if len(r.pids) != maxSymbolizedFrames {
		t.Errorf("resolved %d frames, want %d; grouping must not widen what is resolved",
			len(r.pids), maxSymbolizedFrames)
	}
}
