package probes

import (
	"debug/dwarf"
	"encoding/binary"
	"math"
	"strings"
)

// h3PeerStep / h3PeerPath / h3PeerPaths mirror the structs of the same name in
// bpf/events.h: a DWARF-resolved pointer walk from a hooked Go receiver to the
// quic connection's remote *net.UDPAddr.
type h3PeerStep struct {
	Off   uint32
	Iface uint8
	_     [3]uint8
}

const h3PeerMaxSteps = 6

type h3PeerPath struct {
	NSteps  uint8
	_       [3]uint8
	IPOff   uint32
	PortOff uint32
	Steps   [h3PeerMaxSteps]h3PeerStep
}

type h3PeerPaths struct {
	Client h3PeerPath
	Server h3PeerPath
}

const (
	h3ServerRootType = "github.com/quic-go/quic-go/http3.responseWriter"
	udpAddrType      = "net.UDPAddr"
)

// memberOffset32 validates a DWARF member offset and narrows it to the
// BPF-side u32, rejecting negative or implausibly large offsets rather than
// silently producing a wrong pointer-walk step.
func memberOffset32(off int64) (uint32, bool) {
	if off < 0 || off > maxStructFieldOffset {
		return 0, false
	}
	return uint32(off), true
}

// quicConnImplTypes are the concrete types behind quic-go's client connection
// when the hooked receiver holds it as an interface.
var quicConnImplTypes = []string{
	"github.com/quic-go/quic-go.Conn",
	"github.com/quic-go/quic-go.connection",
}

// sendConnImplTypes are the concrete types behind quic-go's internal sendConn
// interface.
var sendConnImplTypes = []string{"github.com/quic-go/quic-go.sconn"}

// resolveH3PeerPaths builds the client and server peer walks for a target
// binary.
func resolveH3PeerPaths(exePath string, pid uint32, clientRootType string) (paths h3PeerPaths, resolved bool) {
	defer recoverParse("resolveH3PeerPaths")
	d, closeFn, ok := openDWARF(exePath, pid)
	if !ok {
		return h3PeerPaths{}, false
	}
	defer closeFn()

	idx := indexDWARFStructs(d)

	if clientRootType != "" {
		clientPrefix := []string{"conn"}
		if strings.HasSuffix(clientRootType, ".SingleDestinationRoundTripper") {
			clientPrefix = []string{"Connection"}
		}
		if p, ok := buildH3PeerPath(d, idx, clientRootType, clientPrefix); ok {
			paths.Client = p
			resolved = true
		}
	}
	if p, ok := buildH3PeerPath(d, idx, h3ServerRootType, []string{"conn"}); ok {
		paths.Server = p
		resolved = true
	}
	return paths, resolved
}

// openDWARF opens the binary's DWARF, falling back to a build-id /
// .gnu_debuglink debug file.
func openDWARF(exePath string, pid uint32) (data *dwarf.Data, cleanup func(), ok bool) {
	defer recoverParse("openDWARF")
	target, err := openELFCapped(exePath)
	if err != nil {
		return nil, nil, false
	}
	if dwarfWithinCap(target) {
		if d, err := target.DWARF(); err == nil {
			return d, func() { _ = target.Close() }, true
		}
	}
	if dbg, _ := openDebugInfo(target, pid); dbg != nil && dbg != target {
		if dwarfWithinCap(dbg) {
			if d, err := dbg.DWARF(); err == nil {
				return d, func() { _ = dbg.Close(); _ = target.Close() }, true
			}
		}
		_ = dbg.Close()
	}
	_ = target.Close()
	return nil, nil, false
}

// indexDWARFStructs maps struct type names to the DWARF offsets of their
// definitions. Declarations carry no members, so they are skipped in favour of
// the definition wherever it appears.
func indexDWARFStructs(d *dwarf.Data) map[string]dwarf.Offset {
	idx := make(map[string]dwarf.Offset)
	r := d.Reader()
	for {
		ent, err := r.Next()
		if err != nil || ent == nil {
			break
		}
		if ent.Tag != dwarf.TagStructType {
			continue
		}
		if decl, _ := ent.Val(dwarf.AttrDeclaration).(bool); decl {
			continue
		}
		if name, _ := ent.Val(dwarf.AttrName).(string); name != "" {
			if _, seen := idx[name]; !seen {
				idx[name] = ent.Offset
			}
		}
	}
	return idx
}

// dwarfStruct is one struct type read straight from DWARF: its name and its
// direct members, each member's type kept as an offset that is only followed
// when a caller asks. debug/dwarf's Data.Type instead resolves a type's whole
// graph by unbounded recursion, so a hostile chain of type references in a
// traced binary overflows the agent's stack, which recover cannot catch.
type dwarfStruct struct {
	StructName string
	Field      []dwarfMember
}

type dwarfMember struct {
	Name       string
	ByteOffset int64
	Type       dwarf.Offset
	HasType    bool
}

// maxStructMembers bounds how many members readStruct keeps. Real Go structs
// have at most a few hundred.
const maxStructMembers = 1 << 14

// dwarfEntry reads the single entry at off.
func dwarfEntry(d *dwarf.Data, off dwarf.Offset) *dwarf.Entry {
	r := d.Reader()
	r.Seek(off)
	ent, err := r.Next()
	if err != nil || ent == nil || ent.Offset != off {
		return nil
	}
	return ent
}

// readStruct reads the struct definition at off and its direct members.
func readStruct(d *dwarf.Data, off dwarf.Offset) *dwarfStruct {
	r := d.Reader()
	r.Seek(off)
	ent, err := r.Next()
	if err != nil || ent == nil || ent.Offset != off || ent.Tag != dwarf.TagStructType {
		return nil
	}
	st := &dwarfStruct{}
	st.StructName, _ = ent.Val(dwarf.AttrName).(string)
	if !ent.Children {
		return st
	}
	for {
		kid, err := r.Next()
		if err != nil || kid == nil {
			return nil
		}
		if kid.Tag == 0 {
			return st
		}
		if kid.Children {
			r.SkipChildren()
		}
		if kid.Tag != dwarf.TagMember {
			continue
		}
		if len(st.Field) >= maxStructMembers {
			return nil
		}
		m := dwarfMember{}
		m.Name, _ = kid.Val(dwarf.AttrName).(string)
		m.Type, m.HasType = kid.Val(dwarf.AttrType).(dwarf.Offset)
		offset, ok := memberLocation(kid)
		if !ok {
			return nil
		}
		m.ByteOffset = offset
		st.Field = append(st.Field, m)
	}
}

// dwOpPlusUconst is the location opcode older producers use for a member
// offset instead of a constant.
const dwOpPlusUconst = 0x23

// memberLocation decodes DW_AT_data_member_location the way debug/dwarf does:
// a constant, or a DW_OP_plus_uconst expression. A member without one is at
// offset 0.
func memberLocation(kid *dwarf.Entry) (int64, bool) {
	switch loc := kid.Val(dwarf.AttrDataMemberLoc).(type) {
	case int64:
		return loc, true
	case []byte:
		if len(loc) < 2 || loc[0] != dwOpPlusUconst {
			return 0, false
		}
		v, n := binary.Uvarint(loc[1:])
		if n <= 0 || v > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	default:
		return 0, true
	}
}

func structByName(d *dwarf.Data, idx map[string]dwarf.Offset, name string) *dwarfStruct {
	off, ok := idx[name]
	if !ok {
		return nil
	}
	return readStruct(d, off)
}

// buildH3PeerPath walks from a root receiver struct to net.UDPAddr. prefix is
// the member chain to reach the quic connection struct; nil means the single
// member "conn" on the root.
func buildH3PeerPath(d *dwarf.Data, idx map[string]dwarf.Offset, rootType string,
	prefix []string) (h3PeerPath, bool) {
	root := structByName(d, idx, rootType)
	if root == nil {
		return h3PeerPath{}, false
	}
	if prefix == nil {
		prefix = []string{"conn"}
	}

	var steps []h3PeerStep
	cur := root
	for hop := 0; hop < 3 && cur != nil && !hasMember(d, cur, "conn", isGoInterfaceType); hop++ {
		name := "conn"
		if hop < len(prefix) {
			name = prefix[hop]
		}
		next, step, ok := followMember(d, idx, cur, name, quicConnImplTypes)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, step)
		cur = next
	}
	if cur == nil || !hasMember(d, cur, "conn", isGoInterfaceType) {
		return h3PeerPath{}, false
	}

	sconn, step, ok := followMember(d, idx, cur, "conn", sendConnImplTypes)
	if !ok {
		return h3PeerPath{}, false
	}
	steps = append(steps, step)

	udp := structByName(d, idx, udpAddrType)
	if udp == nil {
		return h3PeerPath{}, false
	}
	if f := findMember(sconn, "remoteAddrInfo"); f != nil && f.HasType {
		vOff, inner, ok := atomicPointerInfo(d, f.Type)
		if !ok {
			return h3PeerPath{}, false
		}
		fOff, ok := memberOffset32(f.ByteOffset)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, h3PeerStep{Off: fOff + vOff})
		rai := structByName(d, idx, inner)
		if rai == nil {
			return h3PeerPath{}, false
		}
		addr := findMember(rai, "addr")
		if addr == nil || !addr.HasType || !isGoInterfaceType(d, addr.Type) {
			return h3PeerPath{}, false
		}
		addrOff, ok := memberOffset32(addr.ByteOffset)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, h3PeerStep{Off: addrOff, Iface: 1})
	} else if f := findMember(sconn, "remoteAddr"); f != nil && f.HasType && isGoInterfaceType(d, f.Type) {
		fOff, ok := memberOffset32(f.ByteOffset)
		if !ok {
			return h3PeerPath{}, false
		}
		steps = append(steps, h3PeerStep{Off: fOff, Iface: 1})
	} else {
		return h3PeerPath{}, false
	}

	nsteps := len(steps)
	if nsteps <= 0 || nsteps > h3PeerMaxSteps {
		return h3PeerPath{}, false
	}
	ipField := findMember(udp, "IP")
	portField := findMember(udp, "Port")
	if ipField == nil || portField == nil {
		return h3PeerPath{}, false
	}
	ipOff, ok := memberOffset32(ipField.ByteOffset)
	if !ok {
		return h3PeerPath{}, false
	}
	portOff, ok := memberOffset32(portField.ByteOffset)
	if !ok {
		return h3PeerPath{}, false
	}

	var p h3PeerPath
	p.NSteps = uint8(nsteps)
	p.IPOff = ipOff
	p.PortOff = portOff
	copy(p.Steps[:], steps)
	return p, true
}

// followMember resolves one hop: a pointer member is followed to its target
// struct; an interface member is followed to the first implementing candidate
// present in the binary.
func followMember(d *dwarf.Data, idx map[string]dwarf.Offset, st *dwarfStruct,
	name string, implCandidates []string) (*dwarfStruct, h3PeerStep, bool) {
	f := findMember(st, name)
	if f == nil || !f.HasType {
		return nil, h3PeerStep{}, false
	}
	off, ok := memberOffset32(f.ByteOffset)
	if !ok {
		return nil, h3PeerStep{}, false
	}
	if target, ok := pointerTarget(d, f.Type); ok {
		if ent, targetOff, ok := stripType(d, target); ok && ent.Tag == dwarf.TagStructType {
			if st := readStruct(d, targetOff); st != nil {
				return st, h3PeerStep{Off: off}, true
			}
		}
		return nil, h3PeerStep{}, false
	}
	if isGoInterfaceType(d, f.Type) {
		for _, cand := range implCandidates {
			if impl := structByName(d, idx, cand); impl != nil {
				return impl, h3PeerStep{Off: off, Iface: 1}, true
			}
		}
	}
	return nil, h3PeerStep{}, false
}

func findMember(st *dwarfStruct, name string) *dwarfMember {
	for i := range st.Field {
		if st.Field[i].Name == name {
			return &st.Field[i]
		}
	}
	return nil
}

func hasMember(d *dwarf.Data, st *dwarfStruct, name string, typeCheck func(*dwarf.Data, dwarf.Offset) bool) bool {
	f := findMember(st, name)
	return f != nil && (typeCheck == nil || (f.HasType && typeCheck(d, f.Type)))
}

// maxTypeWrappers bounds how many typedef and qualifier wrappers stripType
// peels, so a typedef that names itself, or a cycle of them, never spins.
const maxTypeWrappers = 16

// stripType follows typedef and qualifier wrappers from the type at off and
// returns the entry underneath and its offset, failing when they do not end
// within maxTypeWrappers.
func stripType(d *dwarf.Data, off dwarf.Offset) (*dwarf.Entry, dwarf.Offset, bool) {
	for range maxTypeWrappers {
		ent := dwarfEntry(d, off)
		if ent == nil {
			return nil, 0, false
		}
		switch ent.Tag {
		case dwarf.TagTypedef, dwarf.TagConstType, dwarf.TagVolatileType, dwarf.TagRestrictType:
			next, ok := ent.Val(dwarf.AttrType).(dwarf.Offset)
			if !ok {
				return nil, 0, false
			}
			off = next
		default:
			return ent, off, true
		}
	}
	return nil, 0, false
}

// pointerTarget returns the offset of the type a pointer type at off points
// to.
func pointerTarget(d *dwarf.Data, off dwarf.Offset) (dwarf.Offset, bool) {
	ent, _, ok := stripType(d, off)
	if !ok || ent.Tag != dwarf.TagPointerType {
		return 0, false
	}
	target, ok := ent.Val(dwarf.AttrType).(dwarf.Offset)
	return target, ok
}

// strippedStruct reads the struct under any wrappers of the type at off.
func strippedStruct(d *dwarf.Data, off dwarf.Offset) *dwarfStruct {
	ent, structOff, ok := stripType(d, off)
	if !ok || ent.Tag != dwarf.TagStructType {
		return nil
	}
	return readStruct(d, structOff)
}

// isGoInterfaceType reports whether a member type is a Go interface (iface or
// eface): a 16-byte two-word struct whose second word is "data".
func isGoInterfaceType(d *dwarf.Data, off dwarf.Offset) bool {
	st := strippedStruct(d, off)
	if st == nil || len(st.Field) != 2 {
		return false
	}
	return st.Field[1].Name == "data" &&
		(st.Field[0].Name == "tab" || st.Field[0].Name == "_type")
}

// atomicPointerInfo returns the offset of the pointer word inside a
// sync/atomic.Pointer[T] member and T's type name.
func atomicPointerInfo(d *dwarf.Data, off dwarf.Offset) (uint32, string, bool) {
	st := strippedStruct(d, off)
	if st == nil || !strings.HasPrefix(st.StructName, "sync/atomic.Pointer[") ||
		!strings.HasSuffix(st.StructName, "]") {
		return 0, "", false
	}
	inner := st.StructName[len("sync/atomic.Pointer[") : len(st.StructName)-1]
	for _, f := range st.Field {
		if f.Name == "v" {
			if off, ok := memberOffset32(f.ByteOffset); ok {
				return off, inner, true
			}
			return 0, "", false
		}
	}
	return 0, "", false
}
