package probes

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"testing"

	"github.com/gma1k/podtrace/internal/safeconv"
)

type dieKind int

const (
	dieStruct dieKind = iota
	dieStructDeclaration
	dieMember
	dieMemberExpression
	diePointer
	dieVoidPointer
	dieTypedef
	dieConst
	dieBase
	dieEnd
	dieLeafStruct
	dieMemberWithoutLocation
	dieMemberRawExpression
	dieTypedefWithoutType
)

type testDIE struct {
	kind dieKind
	name string
	loc  uint64
	ref  int
	expr []byte
}

type dwarfBuilder struct {
	dies      []testDIE
	truncated bool
}

func (b *dwarfBuilder) add(d testDIE) int {
	b.dies = append(b.dies, d)
	return len(b.dies) - 1
}

func (b *dwarfBuilder) structType(name string, members ...testDIE) int {
	idx := b.add(testDIE{kind: dieStruct, name: name})
	for _, m := range members {
		b.add(m)
	}
	b.add(testDIE{kind: dieEnd})
	return idx
}

func (b *dwarfBuilder) structDeclaration(name string) int {
	return b.add(testDIE{kind: dieStructDeclaration, name: name})
}

func (b *dwarfBuilder) pointer(ref int) int {
	return b.add(testDIE{kind: diePointer, ref: ref})
}

func (b *dwarfBuilder) voidPointer() int {
	return b.add(testDIE{kind: dieVoidPointer})
}

func (b *dwarfBuilder) typedef(name string, ref int) int {
	return b.add(testDIE{kind: dieTypedef, name: name, ref: ref})
}

func (b *dwarfBuilder) constType(ref int) int {
	return b.add(testDIE{kind: dieConst, ref: ref})
}

func (b *dwarfBuilder) base(name string) int {
	return b.add(testDIE{kind: dieBase, name: name})
}

func (b *dwarfBuilder) leafStruct(name string) int {
	return b.add(testDIE{kind: dieLeafStruct, name: name})
}

func (b *dwarfBuilder) typedefWithoutType(name string) int {
	return b.add(testDIE{kind: dieTypedefWithoutType, name: name})
}

func memberWithoutLocation(name string, ref int) testDIE {
	return testDIE{kind: dieMemberWithoutLocation, name: name, ref: ref}
}

func memberWithRawExpression(name string, expr []byte, ref int) testDIE {
	return testDIE{kind: dieMemberRawExpression, name: name, expr: expr, ref: ref}
}

func member(name string, loc uint64, ref int) testDIE {
	return testDIE{kind: dieMember, name: name, loc: loc, ref: ref}
}

func memberWithExpression(name string, loc uint64, ref int) testDIE {
	return testDIE{kind: dieMemberExpression, name: name, loc: loc, ref: ref}
}

const (
	abbrevCompileUnit = iota + 1
	abbrevStruct
	abbrevStructDeclaration
	abbrevMember
	abbrevMemberExpression
	abbrevPointer
	abbrevVoidPointer
	abbrevTypedef
	abbrevConst
	abbrevBase
	abbrevLeafStruct
	abbrevMemberWithoutLocation
	abbrevTypedefWithoutType
)

const (
	tagCompileUnit   = 0x11
	tagStructureType = 0x13
	tagMember        = 0x0d
	tagPointerType   = 0x0f
	tagTypedef       = 0x16
	tagConstType     = 0x26
	tagBaseType      = 0x24

	atName               = 0x03
	atDataMemberLocation = 0x38
	atType               = 0x49
	atDeclaration        = 0x3c

	formString      = 0x08
	formUdata       = 0x0f
	formBlock1      = 0x0a
	formRef4        = 0x13
	formFlagPresent = 0x19
)

func dwarfAbbreviations() []byte {
	var out []byte
	entry := func(code, tag byte, children bool, attrs ...[2]byte) {
		out = append(out, code, tag)
		if children {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
		for _, a := range attrs {
			out = append(out, a[0], a[1])
		}
		out = append(out, 0, 0)
	}
	name := [2]byte{atName, formString}
	typ := [2]byte{atType, formRef4}
	entry(abbrevCompileUnit, tagCompileUnit, true)
	entry(abbrevStruct, tagStructureType, true, name)
	entry(abbrevStructDeclaration, tagStructureType, false, name, [2]byte{atDeclaration, formFlagPresent})
	entry(abbrevMember, tagMember, false, name, [2]byte{atDataMemberLocation, formUdata}, typ)
	entry(abbrevMemberExpression, tagMember, false, name, [2]byte{atDataMemberLocation, formBlock1}, typ)
	entry(abbrevPointer, tagPointerType, false, typ)
	entry(abbrevVoidPointer, tagPointerType, false)
	entry(abbrevTypedef, tagTypedef, false, name, typ)
	entry(abbrevConst, tagConstType, false, typ)
	entry(abbrevBase, tagBaseType, false, name)
	entry(abbrevLeafStruct, tagStructureType, false, name)
	entry(abbrevMemberWithoutLocation, tagMember, false, name, typ)
	entry(abbrevTypedefWithoutType, tagTypedef, false, name)
	return append(out, 0)
}

const compileUnitHeaderSize = 11

func (d testDIE) encodedSize() int {
	str := len(d.name) + 1
	switch d.kind {
	case dieStruct, dieStructDeclaration, dieBase, dieLeafStruct, dieTypedefWithoutType:
		return 1 + str
	case dieMemberWithoutLocation:
		return 1 + str + 4
	case dieMemberRawExpression:
		return 1 + str + 1 + len(d.expr) + 4
	case dieMember:
		return 1 + str + len(binary.AppendUvarint(nil, d.loc)) + 4
	case dieMemberExpression:
		return 1 + str + 1 + 1 + len(binary.AppendUvarint(nil, d.loc)) + 4
	case diePointer, dieConst:
		return 1 + 4
	case dieTypedef:
		return 1 + str + 4
	case dieVoidPointer, dieEnd:
		return 1
	}
	panic("unknown DIE kind")
}

func (b *dwarfBuilder) offsets() []dwarf.Offset {
	offs := make([]dwarf.Offset, len(b.dies))
	at := compileUnitHeaderSize + 1
	for i, d := range b.dies {
		offs[i] = dwarf.Offset(at)
		at += d.encodedSize()
	}
	return offs
}

func (b *dwarfBuilder) info() []byte {
	offs := b.offsets()
	var body bytes.Buffer
	body.WriteByte(abbrevCompileUnit)
	ref := func(i int) {
		_ = binary.Write(&body, binary.LittleEndian, uint32(offs[i]))
	}
	str := func(s string) {
		body.WriteString(s)
		body.WriteByte(0)
	}
	for _, d := range b.dies {
		switch d.kind {
		case dieStruct:
			body.WriteByte(abbrevStruct)
			str(d.name)
		case dieStructDeclaration:
			body.WriteByte(abbrevStructDeclaration)
			str(d.name)
		case dieMember:
			body.WriteByte(abbrevMember)
			str(d.name)
			body.Write(binary.AppendUvarint(nil, d.loc))
			ref(d.ref)
		case dieMemberExpression:
			body.WriteByte(abbrevMemberExpression)
			str(d.name)
			expression := append([]byte{dwOpPlusUconst}, binary.AppendUvarint(nil, d.loc)...)
			body.WriteByte(byte(len(expression) & 0xff))
			body.Write(expression)
			ref(d.ref)
		case diePointer:
			body.WriteByte(abbrevPointer)
			ref(d.ref)
		case dieVoidPointer:
			body.WriteByte(abbrevVoidPointer)
		case dieTypedef:
			body.WriteByte(abbrevTypedef)
			str(d.name)
			ref(d.ref)
		case dieConst:
			body.WriteByte(abbrevConst)
			ref(d.ref)
		case dieBase:
			body.WriteByte(abbrevBase)
			str(d.name)
		case dieEnd:
			body.WriteByte(0)
		case dieLeafStruct:
			body.WriteByte(abbrevLeafStruct)
			str(d.name)
		case dieTypedefWithoutType:
			body.WriteByte(abbrevTypedefWithoutType)
			str(d.name)
		case dieMemberWithoutLocation:
			body.WriteByte(abbrevMemberWithoutLocation)
			str(d.name)
			ref(d.ref)
		case dieMemberRawExpression:
			body.WriteByte(abbrevMemberExpression)
			str(d.name)
			body.WriteByte(byte(len(d.expr) & 0xff))
			body.Write(d.expr)
			ref(d.ref)
		}
	}
	if !b.truncated {
		body.WriteByte(0)
	}

	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, safeconv.IntToUint32(body.Len()+7))
	_ = binary.Write(&out, binary.LittleEndian, uint16(4))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	out.WriteByte(8)
	out.Write(body.Bytes())
	return out.Bytes()
}

func (b *dwarfBuilder) data(t *testing.T) *dwarf.Data {
	t.Helper()
	d, err := dwarf.New(dwarfAbbreviations(), nil, nil, b.info(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("dwarf.New: %v", err)
	}
	return d
}

func (b *dwarfBuilder) offset(i int) dwarf.Offset {
	return b.offsets()[i]
}
