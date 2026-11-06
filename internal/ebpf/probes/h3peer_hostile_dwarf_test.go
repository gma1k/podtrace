package probes

import (
	"runtime/debug"
	"testing"
)

func pointerChain(b *dwarfBuilder, length int) int {
	next := b.base("int")
	for range length {
		next = b.pointer(next)
	}
	return next
}

func TestADeepTypeChainDoesNotOverflowTheAgentStack(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(32 << 20))

	var b dwarfBuilder
	head := pointerChain(&b, 400_000)
	b.structType(h3ServerRootType, member("conn", 8, head))
	for _, receiver := range []string{"loopyWriter", "http2Server", "http2Client"} {
		b.structType(grpcTransportPackage+receiver, member("framer", 16, head))
	}
	d := b.data(t)
	idx := indexDWARFStructs(d)

	if _, ok := buildH3PeerPath(d, idx, h3ServerRootType, nil); ok {
		t.Error("built an h3 peer path through a chain of pointers to pointers")
	}
	if off, ok := grpcGoOffsetsFromDWARF(d, idx, grpcTransportPackage); !ok || off.LoopyFramer != 16 {
		t.Errorf("grpc framer offsets = (%+v, %v), want the pointer member at 16", off, ok)
	}
	root := structByName(d, idx, h3ServerRootType)
	if root == nil {
		t.Fatal("the root struct was not read")
	}
	if _, _, ok := followMember(d, idx, root, "conn", nil); ok {
		t.Error("followed a pointer whose target is another pointer")
	}
}

func TestAStructWithTooManyMembersIsRefused(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	members := make([]testDIE, maxStructMembers+1)
	for i := range members {
		members[i] = member("f", uint64(i), word)
	}
	b.structType("huge.T", members...)
	b.structType("small.T", members[:maxStructMembers]...)
	d := b.data(t)
	idx := indexDWARFStructs(d)

	if structByName(d, idx, "huge.T") != nil {
		t.Error("read a struct with more members than any real Go type")
	}
	if st := structByName(d, idx, "small.T"); st == nil || len(st.Field) != maxStructMembers {
		t.Error("refused a struct at the member cap")
	}
}

func TestAStructDeclarationDoesNotShadowItsDefinition(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	b.structDeclaration("net.UDPAddr")
	def := b.structType("net.UDPAddr", member("IP", 0, word), member("Port", 24, word))
	d := b.data(t)
	idx := indexDWARFStructs(d)

	if idx["net.UDPAddr"] != b.offset(def) {
		t.Fatalf("index points at %d, want the definition at %d", idx["net.UDPAddr"], b.offset(def))
	}
	if f := findMember(structByName(d, idx, "net.UDPAddr"), "Port"); f == nil || f.ByteOffset != 24 {
		t.Errorf("Port member = %+v, want offset 24", f)
	}
}

func TestAMemberLocationExpressionIsDecoded(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	b.structType("old.T", memberWithExpression("far", 300, word), member("near", 8, word))
	d := b.data(t)

	st := structByName(d, indexDWARFStructs(d), "old.T")
	if st == nil {
		t.Fatal("struct not read")
	}
	if f := findMember(st, "far"); f == nil || f.ByteOffset != 300 {
		t.Errorf("DW_OP_plus_uconst member = %+v, want offset 300", f)
	}
	if f := findMember(st, "near"); f == nil || f.ByteOffset != 8 {
		t.Errorf("constant member = %+v, want offset 8", f)
	}
}

func TestAVoidPointerMemberIsNotFollowed(t *testing.T) {
	var b dwarfBuilder
	b.structType("t.Root", member("conn", 8, b.voidPointer()))
	d := b.data(t)
	idx := indexDWARFStructs(d)

	if _, _, ok := followMember(d, idx, structByName(d, idx, "t.Root"), "conn", nil); ok {
		t.Error("followed an unsafe.Pointer member to a struct")
	}
}

func quicServerDWARF(b *dwarfBuilder, withAtomicAddress bool) {
	word := b.base("uintptr")
	iface := b.structType("net.Addr", member("tab", 0, word), member("data", 8, word))
	ifaceTypedef := b.typedef("github.com/quic-go/quic-go.sendConn", iface)
	if withAtomicAddress {
		info := b.structType("github.com/quic-go/quic-go.remoteAddrInfo", member("addr", 0, iface))
		atomic := b.structType("sync/atomic.Pointer[github.com/quic-go/quic-go.remoteAddrInfo]",
			member("_", 0, word), member("v", 0, b.pointer(info)))
		b.structType("github.com/quic-go/quic-go.sconn", member("remoteAddrInfo", 48, atomic))
	} else {
		b.structType("github.com/quic-go/quic-go.sconn", member("remoteAddr", 40, iface))
	}
	conn := b.structType("github.com/quic-go/quic-go.connection", member("conn", 24, ifaceTypedef))
	b.structType(h3ServerRootType, member("conn", 8, b.constType(b.pointer(conn))))
	b.structType("net.UDPAddr", member("IP", 0, word), member("Port", 24, word))
}

func TestAQuicServerPeerPathResolvesWithoutDebugDwarfTypes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		atomic bool
		want   []h3PeerStep
	}{
		{"remoteAddr interface", false, []h3PeerStep{{Off: 8}, {Off: 24, Iface: 1}, {Off: 40, Iface: 1}}},
		{"atomic remoteAddrInfo", true, []h3PeerStep{{Off: 8}, {Off: 24, Iface: 1}, {Off: 48}, {Off: 0, Iface: 1}}},
	} {
		var b dwarfBuilder
		quicServerDWARF(&b, tc.atomic)
		d := b.data(t)

		p, ok := buildH3PeerPath(d, indexDWARFStructs(d), h3ServerRootType, nil)
		if !ok {
			t.Errorf("%s: peer path not resolved", tc.name)
			continue
		}
		if int(p.NSteps) != len(tc.want) || p.IPOff != 0 || p.PortOff != 24 {
			t.Errorf("%s: path = %+v, want %d steps and IP/Port at 0/24", tc.name, p, len(tc.want))
			continue
		}
		for i, step := range tc.want {
			if p.Steps[i] != step {
				t.Errorf("%s: step %d = %+v, want %+v", tc.name, i, p.Steps[i], step)
			}
		}
	}
}
