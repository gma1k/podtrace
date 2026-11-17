package safeelf

import (
	"debug/elf"
	"testing"
)

func TestSectionDataWithinReadsExactlyTheSection(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, []rawSection{{name: ".note", typ: elf.SHT_NOTE, data: []byte("build-id")}})
	data, err := SectionDataWithin(f.Section(".note"), MaxNoteSize)
	if err != nil || string(data) != "build-id" {
		t.Errorf("SectionDataWithin = (%q, %v), want build-id", data, err)
	}
}

func TestSectionDataWithinRefusesASectionOverItsLimit(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, []rawSection{{name: ".note", typ: elf.SHT_NOTE, data: make([]byte, 64)}})
	if data, err := SectionDataWithin(f.Section(".note"), 63); err == nil || data != nil {
		t.Errorf("SectionDataWithin = (%d bytes, %v), want a refusal", len(data), err)
	}
	if data, err := SectionDataWithin(nil, 1); data != nil || err != nil {
		t.Errorf("SectionDataWithin(nil) = (%v, %v), want (nil, nil)", data, err)
	}
}

func TestSectionReadsRefuseSectionsWithNoFileData(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, []rawSection{
		{name: ".bss", typ: elf.SHT_NOBITS, declared: 16},
		{name: ".short", typ: elf.SHT_PROGBITS, declared: 1 << 20},
	})
	if _, err := SectionDataWithin(f.Section(".bss"), MaxSectionSize); err == nil {
		t.Error("a SHT_NOBITS section was read")
	}
	if _, err := SectionPrefix(f.Section(".short"), 1<<20); err == nil {
		t.Error("a section running past the end of the file was read")
	}
}

func TestSectionPrefixReadsOnlyTheRequestedBytes(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, []rawSection{{name: ".comment", typ: elf.SHT_PROGBITS, data: []byte("GCC: rustc version 1.90")}})
	data, err := SectionPrefix(f.Section(".comment"), 3)
	if err != nil || string(data) != "GCC" {
		t.Errorf("SectionPrefix = (%q, %v), want GCC", data, err)
	}
	data, err = SectionPrefix(f.Section(".comment"), 1<<20)
	if err != nil || string(data) != "GCC: rustc version 1.90" {
		t.Errorf("SectionPrefix = (%q, %v), want the whole section", data, err)
	}
	if data, err := SectionPrefix(nil, 8); data != nil || err != nil {
		t.Errorf("SectionPrefix(nil) = (%v, %v), want (nil, nil)", data, err)
	}
}

func TestASparseHugeNoteIsRefusedWithoutBeingRead(t *testing.T) {
	path := writeSparseELF(t, []rawSection{{name: ".note.gnu.build-id", typ: elf.SHT_NOTE, declared: 500 << 20}}, 501<<20)
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var readErr error
	if mib := allocatedMiB(func() { _, readErr = SectionDataWithin(f.Section(".note.gnu.build-id"), MaxNoteSize) }); mib > 1 {
		t.Errorf("refusing the note allocated %d MiB", mib)
	}
	if readErr == nil {
		t.Error("a 500 MiB build-id note was read")
	}
}

func TestReadingASectionAllocatesItsSizeOnce(t *testing.T) {
	const size = 64 << 20
	path := writeSparseELF(t, []rawSection{{name: ".big", typ: elf.SHT_PROGBITS, declared: size}}, size+(1<<20))
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var data []byte
	if mib := allocatedMiB(func() { data, err = SectionData(f.Section(".big")) }); mib > size>>20+1 {
		t.Errorf("reading a %d MiB section allocated %d MiB", size>>20, mib)
	}
	if err != nil || len(data) != size {
		t.Errorf("SectionData = (%d bytes, %v), want %d bytes", len(data), err, size)
	}
}
