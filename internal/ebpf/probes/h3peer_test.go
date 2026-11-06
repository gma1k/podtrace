package probes

import (
	"testing"
)

func TestIsGoInterfaceType(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	iface := b.structType("net.Addr", member("tab", 0, word), member("data", 8, word))
	eface := b.structType("interface {}", member("_type", 0, word), member("data", 8, word))
	td := b.typedef("github.com/quic-go/quic-go.sendConn", iface)
	plain := b.structType("net.UDPAddr", member("IP", 0, word), member("Port", 24, word))
	d := b.data(t)

	if !isGoInterfaceType(d, b.offset(iface)) {
		t.Error("iface (tab/data) not recognized")
	}
	if !isGoInterfaceType(d, b.offset(eface)) {
		t.Error("eface (_type/data) not recognized")
	}
	if !isGoInterfaceType(d, b.offset(td)) {
		t.Error("typedef-wrapped interface not recognized")
	}
	if isGoInterfaceType(d, b.offset(plain)) {
		t.Error("plain two-field struct misdetected as interface")
	}
	if isGoInterfaceType(d, b.offset(word)) {
		t.Error("base type misdetected as interface")
	}
}

func TestAtomicPointerInfo(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	ap := b.structType("sync/atomic.Pointer[github.com/quic-go/quic-go.remoteAddrInfo]",
		member("_", 0, word), member("v", 0, word))
	iface := b.structType("net.Addr", member("tab", 0, word), member("data", 8, word))
	d := b.data(t)

	off, inner, ok := atomicPointerInfo(d, b.offset(ap))
	if !ok || off != 0 || inner != "github.com/quic-go/quic-go.remoteAddrInfo" {
		t.Fatalf("atomicPointerInfo = %d %q %v", off, inner, ok)
	}
	if _, _, ok := atomicPointerInfo(d, b.offset(iface)); ok {
		t.Error("interface struct misdetected as atomic.Pointer")
	}
}

func TestStripType(t *testing.T) {
	var b dwarfBuilder
	base := b.structType("x")
	td := b.typedef("y", base)
	d := b.data(t)

	ent, off, ok := stripType(d, b.offset(td))
	if !ok || off != b.offset(base) || ent.Offset != b.offset(base) {
		t.Errorf("stripType = (%v, %d, %v), want the struct at %d", ent, off, ok, b.offset(base))
	}
}
