package safeelf

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func compileUnitAbbrev() []byte {
	return []byte{1, 0x11, 0, 0, 0, 0}
}

func unitV4(abbrevOff uint32, dies ...byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, u32(length(7+len(dies))))
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = binary.LittleEndian.AppendUint32(out, abbrevOff)
	out = append(out, 8)
	return append(out, dies...)
}

func repeatedUnits(n int) []byte {
	unit := unitV4(0)
	return bytes.Repeat(unit, n)
}

func dwarfFile(t *testing.T, fileType elf.Type, secs ...rawSection) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(buildELFOfType(elf.ELFCLASS64, fileType, secs)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func debugSections(abbrev, info []byte) []rawSection {
	return []rawSection{
		{name: ".debug_abbrev", typ: elf.SHT_PROGBITS, data: abbrev},
		{name: ".debug_info", typ: elf.SHT_PROGBITS, data: info},
	}
}

func TestDWARFRefusesARelocatableObject(t *testing.T) {
	f := dwarfFile(t, elf.ET_REL, debugSections(compileUnitAbbrev(), unitV4(0, 1))...)
	if _, err := DWARF(f); !errors.Is(err, errRelocatableDWARF) {
		t.Fatalf("DWARF = %v, want errRelocatableDWARF", err)
	}
}

func TestDWARFAppliesNoRelocationsInAPositionIndependentExecutable(t *testing.T) {
	const relocations = 64 << 20
	secs := append(debugSections(compileUnitAbbrev(), unitV4(0, 1)),
		rawSection{name: ".rela.debug_info", typ: elf.SHT_RELA, info: 2, entsize: 24, declared: relocations},
		rawSection{name: ".debug_str_offsets", typ: elf.SHT_PROGBITS, data: make([]byte, 8)},
		rawSection{name: ".debug_line_str", typ: elf.SHT_PROGBITS, data: []byte("x\x00")},
		rawSection{name: ".debug_addr", typ: elf.SHT_PROGBITS, data: make([]byte, 8)},
	)
	path := filepath.Join(t.TempDir(), "pie")
	if err := os.WriteFile(path, buildELFOfType(elf.ELFCLASS64, elf.ET_DYN, secs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, relocations+(1<<20)); err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	var d *dwarf.Data
	grew := allocatedMiB(func() { d, err = DWARF(f) })
	if err != nil {
		t.Fatalf("DWARF = %v, want the unit read without its relocations", err)
	}
	if grew > 8 {
		t.Errorf("allocated %d MiB beside a %d MiB relocation section it must not read", grew, relocations>>20)
	}
	ent, err := d.Reader().Next()
	if err != nil || ent == nil || ent.Tag != dwarf.TagCompileUnit {
		t.Fatalf("first entry = (%+v, %v), want the compile unit", ent, err)
	}
}

func TestDWARFRefusesMoreUnitsThanTheCap(t *testing.T) {
	f := dwarfFile(t, elf.ET_EXEC, debugSections(compileUnitAbbrev(), repeatedUnits(MaxDWARFUnits+1))...)
	var err error
	grew := allocatedMiB(func() { _, err = DWARF(f) })
	if err == nil {
		t.Fatalf("loaded %d units, over the %d cap", MaxDWARFUnits+1, MaxDWARFUnits)
	}
	if grew > 8 {
		t.Errorf("allocated %d MiB refusing %d units", grew, MaxDWARFUnits+1)
	}
}

func TestDWARFLoadsUnitsUpToTheCap(t *testing.T) {
	f := dwarfFile(t, elf.ET_EXEC, debugSections(compileUnitAbbrev(), repeatedUnits(MaxDWARFUnits))...)
	if _, err := DWARF(f); err != nil {
		t.Fatalf("DWARF = %v, want %d units loaded", err, MaxDWARFUnits)
	}
}

func overlappingAbbrevTables(n int) (abbrev, info []byte) {
	for i := 1; i <= n; i++ {
		info = append(info, unitV4(u32(length(len(abbrev))))...)
		abbrev = binary.AppendUvarint(abbrev, uint64(i))
		abbrev = append(abbrev, 0x11, 0, 0, 0)
	}
	return append(abbrev, 0), info
}

func TestDWARFRefusesUnitsThatEachStartAnAbbreviationTableInsideTheLast(t *testing.T) {
	abbrev, info := overlappingAbbrevTables(2048)
	f := dwarfFile(t, elf.ET_EXEC, debugSections(abbrev, info)...)
	var err error
	grew := allocatedMiB(func() { _, err = DWARF(f) })
	if err == nil {
		t.Fatal("loaded 2048 units that re-parse one 2048-entry abbreviation table from 2048 offsets")
	}
	if grew > 8 {
		t.Errorf("allocated %d MiB refusing overlapping abbreviation tables", grew)
	}
}

func TestDWARFRefusesAnAbbreviationWithMillionsOfAttributes(t *testing.T) {
	const attributes = 3 << 20
	abbrev := append([]byte{1, 0x11, 0}, bytes.Repeat([]byte{0x03, 0x08}, attributes)...)
	abbrev = append(abbrev, 0, 0, 0)
	f := dwarfFile(t, elf.ET_EXEC, debugSections(abbrev, unitV4(0))...)
	var err error
	grew := allocatedMiB(func() { _, err = DWARF(f) })
	if err == nil {
		t.Fatalf("loaded an abbreviation with %d attributes", attributes)
	}
	if grew > 16 {
		t.Errorf("allocated %d MiB refusing a %d MiB abbreviation table", grew, len(abbrev)>>20)
	}
}

func TestDWARFCountsATableSharedByEveryUnitOnce(t *testing.T) {
	abbrev := append([]byte{1, 0x11, 0}, bytes.Repeat([]byte{0x03, 0x08}, 1<<16)...)
	abbrev = append(abbrev, 0, 0, 0)
	f := dwarfFile(t, elf.ET_EXEC, debugSections(abbrev, repeatedUnits(4096))...)
	if _, err := DWARF(f); err != nil {
		t.Fatalf("DWARF = %v, want 4096 units sharing one table loaded", err)
	}
}

func TestDWARFFailsOnADebugSectionWithoutFileData(t *testing.T) {
	f := dwarfFile(t, elf.ET_EXEC,
		rawSection{name: ".debug_abbrev", typ: elf.SHT_NOBITS, declared: 16},
		rawSection{name: ".debug_info", typ: elf.SHT_PROGBITS, data: unitV4(0, 1)})
	if _, err := DWARF(f); err == nil {
		t.Fatal("loaded DWARF whose abbreviation section occupies no file space")
	}
}

func TestDWARFFailsOnTheSizeCap(t *testing.T) {
	f := &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_EXEC}, Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".debug_info", Size: MaxDWARFTotalSize + 1}},
	}}
	if _, err := DWARF(f); err == nil {
		t.Fatal("loaded a .debug_info over the size cap")
	}
}

func TestDWARFPassesOnAnUnsupportedVersionError(t *testing.T) {
	info := unitV4(0, 1)
	binary.LittleEndian.PutUint16(info[4:], 9)
	f := dwarfFile(t, elf.ET_EXEC, debugSections(compileUnitAbbrev(), info)...)
	if _, err := DWARF(f); err == nil {
		t.Fatal("loaded a unit of DWARF version 9")
	}
}

func TestDWARFAbbrevOffsetsOfEveryUnitLayout(t *testing.T) {
	le, be := binary.LittleEndian, binary.BigEndian
	unit64 := le.AppendUint32(nil, 0xffffffff)
	unit64 = le.AppendUint64(unit64, 11)
	unit64 = le.AppendUint16(unit64, 4)
	unit64 = le.AppendUint64(unit64, 0x1234)
	unit64 = append(unit64, 8)

	unit5 := le.AppendUint32(nil, 8)
	unit5 = le.AppendUint16(unit5, 5)
	unit5 = append(unit5, 1, 8)
	unit5 = le.AppendUint32(unit5, 0x55)

	bigEndian := be.AppendUint32(nil, 7)
	bigEndian = be.AppendUint16(bigEndian, 4)
	bigEndian = be.AppendUint32(bigEndian, 0x66)
	bigEndian = append(bigEndian, 8)

	zeroThenUnit := append(le.AppendUint32(nil, 0), unitV4(0x77)...)

	for _, tc := range []struct {
		name string
		info []byte
		want []uint64
	}{
		{"64-bit", unit64, []uint64{0x1234}},
		{"version 5", unit5, []uint64{0x55}},
		{"big-endian", bigEndian, []uint64{0x66}},
		{"empty unit skipped", zeroThenUnit, []uint64{0x77}},
	} {
		got, err := dwarfAbbrevOffsets(tc.info)
		if err != nil || fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: dwarfAbbrevOffsets = (%v, %v), want %v", tc.name, got, err, tc.want)
		}
	}
}

func TestDWARFAbbrevOffsetsStopAtMalformedUnits(t *testing.T) {
	le := binary.LittleEndian
	overlong := unitV4(1)
	le.PutUint32(overlong, 1000)
	reserved := append(unitV4(1), le.AppendUint32(nil, 0xfffffff0)...)
	reserved = append(reserved, 4, 0)
	short64 := append(unitV4(1), le.AppendUint32(nil, 0xffffffff)...)
	short64 = append(short64, 1, 2, 3, 4)
	shortBody := append(unitV4(1), le.AppendUint32(nil, 3)...)
	shortBody = append(shortBody, 4, 0, 0)
	oneByteBody := append(unitV4(1), le.AppendUint32(nil, 1)...)
	oneByteBody = append(oneByteBody, 4)
	trailing := append(unitV4(1), 1, 2)

	for _, tc := range []struct {
		name  string
		info  []byte
		units int
	}{
		{"too short to sniff", []byte{1, 2, 3}, 0},
		{"no byte order", append(le.AppendUint32(nil, 7), 4, 4, 0, 0, 0, 0, 8), 0},
		{"length past the end", overlong, 0},
		{"reserved length", reserved, 1},
		{"truncated 64-bit length", short64, 1},
		{"body too short for the abbreviation offset", shortBody, 1},
		{"body too short for the version", oneByteBody, 1},
		{"trailing bytes", trailing, 1},
	} {
		got, err := dwarfAbbrevOffsets(tc.info)
		if err != nil || len(got) != tc.units {
			t.Errorf("%s: dwarfAbbrevOffsets = (%v, %v), want %d units", tc.name, got, err, tc.units)
		}
	}
}

func TestAbbrevTableCostFollowsTheDecoder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		abbrev []byte
		off    uint64
		want   uint64
	}{
		{"offset past the end", compileUnitAbbrev(), 100, 0},
		{"one entry, one attribute", []byte{1, 0x11, 0, 0x03, 0x08, 0, 0, 0}, 0, abbrevEntryCost + abbrevFieldCost},
		{"implicit constant", []byte{1, 0x11, 0, 0x03, 0x21, 0x7f, 0, 0, 0}, 0, abbrevEntryCost + abbrevFieldCost},
		{"implicit constant cut short", []byte{1, 0x11, 0, 0x03, 0x21}, 0, abbrevEntryCost},
		{"tag cut short", []byte{1}, 0, 0},
		{"children flag cut short", []byte{1, 0x11}, 0, 0},
		{"attributes cut short", []byte{1, 0x11, 0, 0x03}, 0, abbrevEntryCost},
		{"code that truncates to zero ends the table", []byte{0x80, 0x80, 0x80, 0x80, 0x10, 0x11, 0}, 0, 0},
		{"overlong code", append(bytes.Repeat([]byte{0x81}, 11), 0x01, 0x11, 0, 0, 0, 0), 0, abbrevEntryCost},
	} {
		if got := abbrevTableCost(tc.abbrev, tc.off); got != tc.want {
			t.Errorf("%s: abbrevTableCost = %d, want %d", tc.name, got, tc.want)
		}
	}
}
