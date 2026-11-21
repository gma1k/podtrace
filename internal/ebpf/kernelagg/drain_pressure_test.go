package kernelagg

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

func TestAnAbortedIterationStillTakesTheRowsItReached(t *testing.T) {
	f := newFakeMap(
		Row{Key: Key{CgroupID: 1}, Value: Value{Count: 2}},
		Row{Key: Key{CgroupID: 2}, Value: Value{Count: 3}},
	)
	f.err = fmt.Errorf("%w", ebpf.ErrIterationAborted)

	rows, taken, err := drainRowsCounted(f.next, f.errFn, f.take)
	if err != nil {
		t.Fatalf("an aborted walk failed the drain: %v", err)
	}
	if len(rows) != 2 || taken != 2 {
		t.Fatalf("rows = %d, taken = %d; want both rows reached before the abort", len(rows), taken)
	}
	if len(f.rows) != 0 {
		t.Errorf("%d reached rows stayed in the map", len(f.rows))
	}
}

func TestARestartedWalkTakesEachKeyOnce(t *testing.T) {
	a, b := Key{CgroupID: 1}, Key{CgroupID: 2}
	f := newFakeMap(
		Row{Key: a, Value: Value{Count: 1}},
		Row{Key: b, Value: Value{Count: 1}},
	)
	f.order = []Key{a, b, a, b, a}

	rows, taken, err := drainRowsCounted(f.next, f.errFn, f.take)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.taken) != 2 || taken != 2 || len(rows) != 2 {
		t.Fatalf("took %d keys (%d counted, %d rows), want each of the 2 keys once", len(f.taken), taken, len(rows))
	}
}

func TestTakenCountsEmptyRowsButNotFailedOnes(t *testing.T) {
	stuck := Key{CgroupID: 3}
	f := newFakeMap(
		Row{Key: Key{CgroupID: 1}, Value: Value{}},
		Row{Key: Key{CgroupID: 2}, Value: Value{Count: 1}},
		Row{Key: stuck, Value: Value{Count: 1}},
	)
	take := func(k *Key) (Value, error) {
		if *k == stuck {
			return Value{}, errors.New("take exploded")
		}
		return f.take(k)
	}

	rows, taken, err := drainRowsCounted(f.next, f.errFn, take)
	if err == nil {
		t.Fatal("the take failure was swallowed")
	}
	if taken != 2 || len(rows) != 1 {
		t.Fatalf("taken = %d, rows = %d; want 2 removed and 1 reported", taken, len(rows))
	}
}

func TestAnotherIterationFailureStillFailsTheDrain(t *testing.T) {
	f := newFakeMap(Row{Key: Key{CgroupID: 1}, Value: Value{Count: 1}})
	f.err = errors.New("get next key: permission denied")

	rows, taken, err := drainRowsCounted(f.next, f.errFn, f.take)
	if err == nil || rows != nil || taken != 0 {
		t.Fatalf("rows = %v, taken = %d, err = %v; want the failure surfaced and nothing taken", rows, taken, err)
	}
	if len(f.taken) != 0 {
		t.Error("rows were removed although the walk failed for a reason other than an abort")
	}
}

func TestDrainCountedRejectsANilMap(t *testing.T) {
	if _, _, err := DrainCounted(nil); err == nil {
		t.Error("DrainCounted(nil) returned no error")
	}
}

type fakeConfigMap struct {
	cfg       Config
	lookupErr error
	updateErr error
	updates   int
}

func (m *fakeConfigMap) Lookup(_, valueOut any) error {
	if m.lookupErr != nil {
		return m.lookupErr
	}
	*(valueOut.(*Config)) = m.cfg
	return nil
}

func (m *fakeConfigMap) Update(_, value any, _ ebpf.MapUpdateFlags) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updates++
	m.cfg = *(value.(*Config))
	return nil
}

func TestSettingTheRowBudgetKeepsTheGeneration(t *testing.T) {
	m := &fakeConfigMap{cfg: Config{CgroupRowBudget: 1, Generation: 7}}

	if err := SetCgroupRowBudget(m, 4096); err != nil {
		t.Fatal(err)
	}
	if m.cfg != (Config{CgroupRowBudget: 4096, Generation: 7}) {
		t.Errorf("config = %+v; resetting the generation would let every cgroup carry its old row count into a new interval", m.cfg)
	}
}

func TestAdvancingTheGenerationKeepsTheBudget(t *testing.T) {
	m := &fakeConfigMap{cfg: Config{CgroupRowBudget: 4096, Generation: 0xFFFFFFFF}}

	if err := AdvanceGeneration(m); err != nil {
		t.Fatal(err)
	}
	if m.cfg != (Config{CgroupRowBudget: 4096, Generation: 0}) {
		t.Errorf("config = %+v, want the budget kept and the generation wrapped", m.cfg)
	}
}

func TestBudgetConfigFailuresAreReported(t *testing.T) {
	if err := SetCgroupRowBudget(nil, 1); err == nil {
		t.Error("SetCgroupRowBudget(nil) returned no error")
	}
	if err := AdvanceGeneration(nil); err == nil {
		t.Error("AdvanceGeneration(nil) returned no error")
	}
	for name, m := range map[string]*fakeConfigMap{
		"lookup": {lookupErr: errors.New("lookup exploded")},
		"update": {updateErr: errors.New("update exploded")},
	} {
		if err := SetCgroupRowBudget(m, 1); err == nil {
			t.Errorf("SetCgroupRowBudget swallowed a %s failure", name)
		}
		if err := AdvanceGeneration(m); err == nil {
			t.Errorf("AdvanceGeneration swallowed a %s failure", name)
		}
		if m.updates != 0 {
			t.Errorf("%s failure: the config was still written", name)
		}
	}
}

type fakeStatsMap struct {
	slots map[uint32][]uint64
	err   map[uint32]error
}

func (m *fakeStatsMap) Lookup(key, valueOut any) error {
	slot := *(key.(*uint32))
	if err := m.err[slot]; err != nil {
		return err
	}
	*(valueOut.(*[]uint64)) = m.slots[slot]
	return nil
}

func TestReadStatsSumsEveryCPU(t *testing.T) {
	m := &fakeStatsMap{slots: map[uint32][]uint64{
		statRowsCreated:   {3, 4, 5},
		statPeerCollapsed: {0, 9},
	}}

	got, err := ReadStats(m)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Stats{RowsCreated: 12, PeerCollapsed: 9}) {
		t.Errorf("ReadStats = %+v", got)
	}
}

func TestReadStatsReportsFailures(t *testing.T) {
	if _, err := ReadStats(nil); err == nil {
		t.Error("ReadStats(nil) returned no error")
	}
	for _, slot := range []uint32{statRowsCreated, statPeerCollapsed} {
		m := &fakeStatsMap{
			slots: map[uint32][]uint64{statRowsCreated: {1}, statPeerCollapsed: {1}},
			err:   map[uint32]error{slot: errors.New("lookup exploded")},
		}
		if _, err := ReadStats(m); err == nil {
			t.Errorf("a failed read of slot %d was swallowed", slot)
		}
	}
}

func TestPressureCountsRowsCreatedButNeverTaken(t *testing.T) {
	var p PressureTracker

	if got := p.Observe(Stats{RowsCreated: 10}, 10); got.RowsEvicted != 0 {
		t.Fatalf("evicted = %d after a drain took every row", got.RowsEvicted)
	}
	if got := p.Observe(Stats{RowsCreated: 25}, 9); got.RowsEvicted != 6 {
		t.Fatalf("evicted = %d, want the 6 rows created before the drain that it never found", got.RowsEvicted)
	}
	if got := p.Pressure(); got.RowsEvicted != 6 {
		t.Errorf("Pressure() = %+v, want the last observation", got)
	}
}

func TestPressureNeverDropsWhenADrainTakesRowsCreatedAfterTheRead(t *testing.T) {
	var p PressureTracker
	p.Observe(Stats{RowsCreated: 10}, 6)

	got := p.Observe(Stats{RowsCreated: 10}, 8)
	if got.RowsEvicted != 4 {
		t.Errorf("evicted = %d, want the 4 already counted kept as a lower bound", got.RowsEvicted)
	}
	got = p.Observe(Stats{RowsCreated: 12, PeerCollapsed: 3}, -1)
	if got.RowsEvicted != 4 || got.PeerCollapsed != 3 {
		t.Errorf("pressure = %+v", got)
	}
	if got := p.Observe(Stats{PeerCollapsed: 1}, 0); got.PeerCollapsed != 3 {
		t.Errorf("peer collapsed fell to %d", got.PeerCollapsed)
	}
}
