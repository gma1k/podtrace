package probes

import (
	"debug/dwarf"
	"testing"
	"time"
)

func TestASelfReferentialTypedefDoesNotSpinForever(t *testing.T) {
	var b dwarfBuilder
	self := b.typedef("self", 0)
	b.dies[self].ref = self
	first := b.typedef("a", 0)
	second := b.constType(first)
	b.dies[first].ref = second
	d := b.data(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, ok := stripType(d, b.offset(self)); ok {
			t.Error("stripType(self-typedef) resolved, want failure")
		}
		if _, _, ok := stripType(d, b.offset(first)); ok {
			t.Error("stripType(typedef cycle) resolved, want failure")
		}
		if isGoInterfaceType(d, b.offset(self)) {
			t.Error("a self-referential typedef was taken for an interface")
		}
		if _, _, ok := atomicPointerInfo(d, b.offset(self)); ok {
			t.Error("a self-referential typedef was taken for an atomic pointer")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stripType never returned on a typedef that names itself")
	}
}

func TestStripTypeStillPeelsAnOrdinaryChain(t *testing.T) {
	var b dwarfBuilder
	base := b.structType("net.UDPAddr")
	chain := b.typedef("wrapped", b.constType(base))
	d := b.data(t)

	ent, off, ok := stripType(d, b.offset(chain))
	if !ok || off != b.offset(base) || ent.Val(dwarf.AttrName) != "net.UDPAddr" {
		t.Errorf("stripType = (%v, %d, %v), want the struct under the wrappers", ent, off, ok)
	}
}
