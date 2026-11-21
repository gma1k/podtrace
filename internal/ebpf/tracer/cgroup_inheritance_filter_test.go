package tracer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/events"
)

func inheritedMapTracer(t *testing.T, children map[uint64]uint64) *Tracer {
	t.Helper()
	inherited, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	for child, parent := range children {
		if err := inherited.Put(child, parent); err != nil {
			t.Fatal(err)
		}
	}
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{inheritedCgroupMapName: inherited}}}
	t.Cleanup(tr.collection.Close)
	return tr
}

func TestAnInheritedCgroupTheFilterRefusesIsNotTraced(t *testing.T) {
	tr := inheritedMapTracer(t, map[uint64]uint64{200: 50, 201: 50})
	tr.storeCgroupIDs(map[uint64]struct{}{100: {}})
	var asked [][2]uint64
	tr.SetInheritedCgroupFilter(func(child, parent uint64) InheritedCgroupVerdict {
		asked = append(asked, [2]uint64{child, parent})
		if child == 200 {
			return InheritedCgroupAdmit
		}
		return InheritedCgroupUndecided
	})

	if parent, ok := tr.InheritedCgroupParent(200); !ok || parent != 50 {
		t.Fatalf("InheritedCgroupParent(200) = %d, %v; want the admitted child kept", parent, ok)
	}
	if _, ok := tr.InheritedCgroupParent(201); ok {
		t.Fatal("a child the filter refused was inherited")
	}
	if tr.cgroupAllows(&events.Event{CgroupID: 201}) {
		t.Fatal("an event from a refused child passed the cgroup gate")
	}
	if len(asked) != 3 || asked[0] != [2]uint64{200, 50} {
		t.Fatalf("filter asked %v", asked)
	}

	tr.InheritedCgroupParent(200)
	if len(asked) != 3 {
		t.Error("an admitted child was asked again instead of being remembered")
	}
}

func TestAnUndecidedChildIsAskedAgainSoAFilterCanFinishVerifying(t *testing.T) {
	tr := inheritedMapTracer(t, map[uint64]uint64{200: 50})
	verdict := InheritedCgroupUndecided
	tr.SetInheritedCgroupFilter(func(uint64, uint64) InheritedCgroupVerdict { return verdict })

	if _, ok := tr.InheritedCgroupParent(200); ok {
		t.Fatal("admitted before the filter agreed")
	}
	var parent uint64
	if err := tr.collection.Maps[inheritedCgroupMapName].Lookup(uint64(200), &parent); err != nil {
		t.Fatalf("an undecided child was removed from the kernel map: %v", err)
	}
	verdict = InheritedCgroupAdmit
	if _, ok := tr.InheritedCgroupParent(200); !ok {
		t.Fatal("an undecided answer was remembered, so a child verified late is never traced")
	}
}

func TestRemovingTheFilterRestoresWholePodInheritance(t *testing.T) {
	tr := inheritedMapTracer(t, map[uint64]uint64{200: 50})
	tr.SetInheritedCgroupFilter(func(uint64, uint64) InheritedCgroupVerdict { return InheritedCgroupRefuse })
	tr.SetInheritedCgroupFilter(nil)

	if _, ok := tr.InheritedCgroupParent(200); !ok {
		t.Fatal("a child was refused with no filter installed")
	}
}

func TestSetInheritedCgroupFilterOnANilTracerIsANoop(t *testing.T) {
	var tr *Tracer
	tr.SetInheritedCgroupFilter(func(uint64, uint64) InheritedCgroupVerdict { return InheritedCgroupAdmit })
}

func TestARefusedChildIsRemovedFromTheKernelMap(t *testing.T) {
	tr := inheritedMapTracer(t, map[uint64]uint64{200: 50})
	tr.SetInheritedCgroupFilter(func(uint64, uint64) InheritedCgroupVerdict { return InheritedCgroupRefuse })

	if _, ok := tr.InheritedCgroupParent(200); ok {
		t.Fatal("a refused child was inherited")
	}
	var parent uint64
	if err := tr.collection.Maps[inheritedCgroupMapName].Lookup(uint64(200), &parent); err == nil {
		t.Fatal("a refused child is still in inherited_cgroup_ids, so the kernel keeps emitting its events")
	}
	if _, ok := tr.InheritedCgroupParent(200); ok {
		t.Fatal("a refused child was inherited on a later event")
	}
}

type recordingInheritedDeleter struct {
	err     error
	deleted []uint64
}

func (d *recordingInheritedDeleter) Delete(key any) error {
	d.deleted = append(d.deleted, *key.(*uint64))
	return d.err
}

func TestForgettingARefusedChildDeletesItsKernelEntry(t *testing.T) {
	for name, err := range map[string]error{
		"deleted":         nil,
		"already gone":    fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist),
		"delete rejected": errors.New("operation not permitted"),
	} {
		t.Run(name, func(t *testing.T) {
			d := &recordingInheritedDeleter{err: err}
			forgetRefusedInheritedCgroup(d, 4242)
			if len(d.deleted) != 1 || d.deleted[0] != 4242 {
				t.Fatalf("deleted %v, want [4242]", d.deleted)
			}
		})
	}
}
