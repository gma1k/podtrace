package kernelagg

import (
	"testing"

	"github.com/cilium/ebpf"
)

type sharedRowMap struct {
	scriptedRowMap
}

func (m *sharedRowMap) LookupAndDelete(key, valueOut any) error {
	m.atomicCalls++
	if m.lookupAndDel != nil {
		return m.lookupAndDel
	}
	k := *(key.(*Key))
	v, ok := m.rows[k]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*(valueOut.(*Value)) = v
	delete(m.rows, k)
	return nil
}

func (m *sharedRowMap) Lookup(key, valueOut any) error {
	m.separateLookup++
	v, ok := m.rows[*(key.(*Key))]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*(valueOut.(*Value)) = v
	return nil
}

func TestARowOfASharedMapIsTakenAsOneValue(t *testing.T) {
	k := Key{CgroupID: 3}
	m := &sharedRowMap{scriptedRowMap{rows: map[Key]Value{k: {Count: 7, SumNS: 70, Bytes: 9}}}}
	v, err := (&mapTaker{m: m, shared: true}).take(&k)
	if err != nil || v != (Value{Count: 7, SumNS: 70, Bytes: 9}) {
		t.Fatalf("take = %+v, %v; want the row's single value", v, err)
	}
	if len(m.rows) != 0 || m.separateLookup != 0 {
		t.Error("the row was not taken in one step")
	}
}

func TestASharedMapFallsBackToLookupThenDelete(t *testing.T) {
	k := Key{CgroupID: 4}
	m := &sharedRowMap{scriptedRowMap{rows: map[Key]Value{k: {Count: 2}}, lookupAndDel: ebpf.ErrNotSupported}}
	taker := &mapTaker{m: m, shared: true}
	v, err := taker.take(&k)
	if err != nil || v.Count != 2 || len(m.rows) != 0 {
		t.Fatalf("take = %+v, %v with %d rows left; want the value and the row removed", v, err, len(m.rows))
	}
	if v, err := taker.take(&k); err != nil || v != (Value{}) {
		t.Errorf("taking a removed row = %+v, %v; want zero", v, err)
	}
}

func TestOnlyPerCPUMapTypesAreSummedAcrossCPUs(t *testing.T) {
	for typ, want := range map[ebpf.MapType]bool{
		ebpf.LRUCPUHash:  true,
		ebpf.PerCPUHash:  true,
		ebpf.PerCPUArray: true,
		ebpf.LRUHash:     false,
		ebpf.Hash:        false,
	} {
		if got := perCPUMap(typ); got != want {
			t.Errorf("perCPUMap(%v) = %v, want %v", typ, got, want)
		}
	}
}
