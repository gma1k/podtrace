package probes

import (
	"debug/dwarf"
	"testing"
)

func ifaceStruct(name string, firstField string) *dwarf.StructType {
	return &dwarf.StructType{
		StructName: name,
		Kind:       "struct",
		Field: []*dwarf.StructField{
			{Name: firstField, ByteOffset: 0},
			{Name: "data", ByteOffset: 8},
		},
	}
}

func TestIsGoInterfaceType(t *testing.T) {
	iface := ifaceStruct("net.Addr", "tab")
	if !isGoInterfaceType(iface) {
		t.Error("iface (tab/data) not recognized")
	}
	eface := ifaceStruct("interface {}", "_type")
	if !isGoInterfaceType(eface) {
		t.Error("eface (_type/data) not recognized")
	}
	td := &dwarf.TypedefType{Type: iface}
	td.Name = "github.com/quic-go/quic-go.sendConn"
	if !isGoInterfaceType(td) {
		t.Error("typedef-wrapped interface not recognized")
	}
	plain := &dwarf.StructType{
		StructName: "net.UDPAddr",
		Kind:       "struct",
		Field: []*dwarf.StructField{
			{Name: "IP", ByteOffset: 0},
			{Name: "Port", ByteOffset: 24},
		},
	}
	if isGoInterfaceType(plain) {
		t.Error("plain two-field struct misdetected as interface")
	}
}

func TestAtomicPointerInfo(t *testing.T) {
	ap := &dwarf.StructType{
		StructName: "sync/atomic.Pointer[github.com/quic-go/quic-go.remoteAddrInfo]",
		Kind:       "struct",
		Field: []*dwarf.StructField{
			{Name: "_", ByteOffset: 0},
			{Name: "v", ByteOffset: 0},
		},
	}
	off, inner, ok := atomicPointerInfo(ap)
	if !ok || off != 0 || inner != "github.com/quic-go/quic-go.remoteAddrInfo" {
		t.Fatalf("atomicPointerInfo = %d %q %v", off, inner, ok)
	}
	if _, _, ok := atomicPointerInfo(ifaceStruct("net.Addr", "tab")); ok {
		t.Error("interface struct misdetected as atomic.Pointer")
	}
}

func TestStripType(t *testing.T) {
	base := &dwarf.StructType{StructName: "x", Kind: "struct"}
	td := &dwarf.TypedefType{Type: base}
	if stripType(td) != dwarf.Type(base) {
		t.Error("typedef not stripped")
	}
}
