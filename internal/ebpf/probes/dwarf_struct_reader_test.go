package probes

import (
	"debug/dwarf"
	"testing"
)

func TestReadStructRefusesAnOffsetThatIsNotAStruct(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	d := b.data(t)

	if readStruct(d, b.offset(word)) != nil {
		t.Error("read a base type as a struct")
	}
	if readStruct(d, b.offset(word)+1) != nil {
		t.Error("read a struct from the middle of an entry")
	}
}

func TestAStructWithoutChildrenHasNoMembers(t *testing.T) {
	var b dwarfBuilder
	leaf := b.leafStruct("empty.T")
	d := b.data(t)

	st := readStruct(d, b.offset(leaf))
	if st == nil || st.StructName != "empty.T" || len(st.Field) != 0 {
		t.Errorf("readStruct = %+v, want empty.T with no members", st)
	}
}

func TestANestedTypeInsideAStructIsSkipped(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	outer := b.add(testDIE{kind: dieStruct, name: "outer.T"})
	b.structType("outer.inner", member("hidden", 0, word))
	b.add(member("visible", 16, word))
	b.add(testDIE{kind: dieEnd})
	d := b.data(t)

	st := readStruct(d, b.offset(outer))
	if st == nil || len(st.Field) != 1 || st.Field[0].Name != "visible" || st.Field[0].ByteOffset != 16 {
		t.Errorf("readStruct = %+v, want only the outer member visible at 16", st)
	}
}

func TestAStructCutOffByTheEndOfItsUnitIsRefused(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	cut := b.add(testDIE{kind: dieStruct, name: "cut.T"})
	b.add(member("a", 0, word))
	b.truncated = true
	d := b.data(t)

	if st := readStruct(d, b.offset(cut)); st != nil {
		t.Errorf("readStruct = %+v, want nil for members that never terminate", st)
	}
}

func TestMemberLocationsDecodeLikeDebugDwarf(t *testing.T) {
	var b dwarfBuilder
	word := b.base("uintptr")
	good := b.structType("good.T", memberWithoutLocation("first", word), memberWithExpression("far", 300, word))
	wrongOpcode := b.structType("wrong.T", memberWithRawExpression("x", []byte{0x10, 4}, word))
	noOperand := b.structType("short.T", memberWithRawExpression("x", []byte{dwOpPlusUconst}, word))
	overflow := b.structType("overflow.T", memberWithRawExpression("x",
		[]byte{dwOpPlusUconst, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, word))
	badVarint := b.structType("varint.T", memberWithRawExpression("x", []byte{dwOpPlusUconst, 0x80}, word))
	d := b.data(t)

	st := readStruct(d, b.offset(good))
	if st == nil || len(st.Field) != 2 || st.Field[0].ByteOffset != 0 || st.Field[1].ByteOffset != 300 {
		t.Errorf("readStruct = %+v, want first at 0 and far at 300", st)
	}
	for name, off := range map[string]dwarf.Offset{
		"wrong opcode": b.offset(wrongOpcode),
		"no operand":   b.offset(noOperand),
		"over int64":   b.offset(overflow),
		"bad varint":   b.offset(badVarint),
	} {
		if st := readStruct(d, off); st != nil {
			t.Errorf("%s: readStruct = %+v, want nil", name, st)
		}
	}
}

func TestStripTypeFailsOnABrokenReference(t *testing.T) {
	var b dwarfBuilder
	untyped := b.typedefWithoutType("void.T")
	word := b.base("uintptr")
	d := b.data(t)

	if _, _, ok := stripType(d, b.offset(untyped)); ok {
		t.Error("stripped a typedef that names no type")
	}
	if _, _, ok := stripType(d, b.offset(word)+1); ok {
		t.Error("stripped a type at an offset no entry starts at")
	}
}
