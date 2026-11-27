package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
)

type fakeInflightCounts struct {
	counts map[uint64]int32
}

func (f *fakeInflightCounts) Put(key, value any) error {
	f.counts[key.(uint64)] = value.(int32)
	return nil
}

func (f *fakeInflightCounts) Delete(key any) error {
	if _, ok := f.counts[key.(uint64)]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.counts, key.(uint64))
	return nil
}

func TestTheSweepRewritesEachCgroupsInflightCountFromTheMap(t *testing.T) {
	m := &fakeInflightCounts{counts: map[uint64]int32{1: 4096, 2: 3, 3: -1, 4: 9}}
	writeDNSInflightCounts(m, []uint64{1, 2, 3, 4}, map[uint64]int32{1: 12, 2: 0, 5: 7})

	want := map[uint64]int32{1: 12, 5: 7}
	if len(m.counts) != len(want) {
		t.Fatalf("counts %v, want %v", m.counts, want)
	}
	for cgroup, count := range want {
		if m.counts[cgroup] != count {
			t.Errorf("cgroup %d count %d, want %d", cgroup, m.counts[cgroup], count)
		}
	}
}

func TestTheInflightCountSyncNeedsTheCountMap(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	tr.syncDNSInflightCounts(map[uint64]int32{1: 1})
}
