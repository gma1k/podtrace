package tracer

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeEventSlots struct {
	valueSize uint32
	races     map[uint32][]uint64
	err       error
}

func (f *fakeEventSlots) ValueSize() uint32 { return f.valueSize }

func (f *fakeEventSlots) LookupBytes(key interface{}) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	size := int(f.valueSize)
	var out []byte
	for _, races := range f.races[key.(uint32)] {
		value := make([]byte, size)
		for i := range value[:size-8] {
			value[i] = 0xAA
		}
		binary.NativeEndian.PutUint64(value[size-8:], races)
		out = append(out, value...)
	}
	return out, nil
}

func TestReadEventSlotRacesSumsEveryCPUAndSlot(t *testing.T) {
	got, err := readEventSlotRaces(&fakeEventSlots{
		valueSize: 448,
		races:     map[uint32][]uint64{0: {3, 0}, 1: {0, 4}, 2: {1, 0}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 8 {
		t.Errorf("readEventSlotRaces = %d, want 8", got)
	}
}

func TestReadEventSlotRacesRejectsAValueWithoutCounter(t *testing.T) {
	if _, err := readEventSlotRaces(&fakeEventSlots{valueSize: 4}); err == nil {
		t.Error("a value too small to hold the counter must be an error")
	}
}

func TestRecordEventSlotRacesReportsOnlyTheIncrease(t *testing.T) {
	tr := &Tracer{}
	var reasons []string
	var counts []int
	tr.SetDropReporter(func(reason string, n int) {
		reasons = append(reasons, reason)
		counts = append(counts, n)
	})
	slots := &fakeEventSlots{valueSize: 448, races: map[uint32][]uint64{0: {2, 3}}}
	tr.recordEventSlotRaces(slots)
	tr.recordEventSlotRaces(slots)
	slots.races[0] = []uint64{4, 3}
	tr.recordEventSlotRaces(slots)

	if len(counts) != 2 || counts[0] != 5 || counts[1] != 2 {
		t.Fatalf("reported counts = %v, want [5 2]", counts)
	}
	for _, r := range reasons {
		if r != eventSlotRaceReason {
			t.Errorf("reason = %q, want %q", r, eventSlotRaceReason)
		}
	}
}

func TestRecordEventSlotRacesIgnoresLookupFailure(t *testing.T) {
	tr := &Tracer{}
	reported := false
	tr.SetDropReporter(func(string, int) { reported = true })
	tr.recordEventSlotRaces(&fakeEventSlots{valueSize: 448, err: errors.New("no map")})
	if reported {
		t.Error("a failed lookup must not report drops")
	}
	if tr.eventSlotRaces.Load() != 0 {
		t.Error("a failed lookup must not move the baseline")
	}
}

func TestPollEventSlotRacesWithoutCollectionIsANoop(t *testing.T) {
	tr := &Tracer{}
	tr.pollEventSlotRaces()
}

func TestPollEventSlotRacesSkipsACollectionWithoutTheSlotMap(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	reported := false
	tr.SetDropReporter(func(string, int) { reported = true })
	tr.pollEventSlotRaces()
	if reported {
		t.Error("no slot map must mean no drop report")
	}
}

func TestPollEventSlotRacesReadsTheSlotMapOnEveryMapPoll(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{eventSlotMapName: {}}}}
	reported := false
	tr.SetDropReporter(func(string, int) { reported = true })
	tr.pollBPFMapUtilization()
	if reported {
		t.Error("an unreadable slot map must not report drops")
	}
	if tr.eventSlotRaces.Load() != 0 {
		t.Error("an unreadable slot map must not move the baseline")
	}
}
