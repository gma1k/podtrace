package usdt_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/usdt"
)

// buildNoteEntry constructs a single ELF note entry with the given type, name, and descriptor.
func buildNoteEntry(noteType uint32, name string, desc []byte) []byte {
	le := binary.LittleEndian
	noteName := name + "\x00"

	// Pad desc to 4-byte boundary.
	paddedDesc := make([]byte, len(desc))
	copy(paddedDesc, desc)
	for len(paddedDesc)%4 != 0 {
		paddedDesc = append(paddedDesc, 0)
	}

	var note []byte
	b4 := make([]byte, 4)
	le.PutUint32(b4, uint32(len(noteName)))
	note = append(note, b4...)
	le.PutUint32(b4, uint32(len(desc)))
	note = append(note, b4...)
	le.PutUint32(b4, noteType)
	note = append(note, b4...)
	note = append(note, []byte(noteName)...)
	for len(note)%4 != 0 {
		note = append(note, 0)
	}
	note = append(note, paddedDesc...)
	return note
}

// buildELFWithNoteData creates a minimal ELF64 LE binary with a .note.stapsdt
// section containing the given raw bytes, then returns the file path.
func buildELFWithNoteData(t *testing.T, noteData []byte) string {
	t.Helper()

	shstrNames := "\x00.note.stapsdt\x00.shstrtab\x00"
	shstrOffset := 1
	noteSecNameIdx := shstrOffset

	const elfHeaderSize = 64
	const shEntrySize = 64
	const numSections = 3 // null + note + shstrtab

	noteOff := uint64(elfHeaderSize)
	shstrDataOff := noteOff + uint64(len(noteData))
	if shstrDataOff%8 != 0 {
		shstrDataOff += 8 - shstrDataOff%8
	}
	shOff := shstrDataOff + uint64(len(shstrNames))
	if shOff%8 != 0 {
		shOff += 8 - shOff%8
	}

	totalSize := int(shOff) + numSections*shEntrySize
	buf := make([]byte, totalSize)
	le := binary.LittleEndian

	// ELF magic + header.
	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT
	buf[7] = 0 // ELFOSABI_NONE
	le.PutUint16(buf[16:], 2)              // ET_EXEC
	le.PutUint16(buf[18:], 62)             // EM_X86_64
	le.PutUint32(buf[20:], 1)              // EV_CURRENT
	le.PutUint64(buf[40:], shOff)          // e_shoff
	le.PutUint32(buf[48:], 0)             // e_flags
	le.PutUint16(buf[52:], elfHeaderSize)  // e_ehsize
	le.PutUint16(buf[54:], 56)            // e_phentsize
	le.PutUint16(buf[56:], 0)             // e_phnum
	le.PutUint16(buf[58:], shEntrySize)   // e_shentsize
	le.PutUint16(buf[60:], uint16(numSections)) // e_shnum
	le.PutUint16(buf[62:], 2)             // e_shstrndx

	// Note data.
	copy(buf[noteOff:], noteData)
	// shstrtab data.
	copy(buf[shstrDataOff:], shstrNames)

	writeShdr := func(idx int, nameIdx uint32, shType uint32, flags, addr, off, size uint64, link, info, addralign, entsize uint64) {
		base := int(shOff) + idx*shEntrySize
		le.PutUint32(buf[base:], nameIdx)
		le.PutUint32(buf[base+4:], shType)
		le.PutUint64(buf[base+8:], flags)
		le.PutUint64(buf[base+16:], addr)
		le.PutUint64(buf[base+24:], off)
		le.PutUint64(buf[base+32:], size)
		le.PutUint32(buf[base+40:], uint32(link))
		le.PutUint32(buf[base+44:], uint32(info))
		le.PutUint64(buf[base+48:], addralign)
		le.PutUint64(buf[base+56:], entsize)
	}
	writeShdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // null
	writeShdr(1, uint32(noteSecNameIdx), 7 /*SHT_NOTE*/, 0, 0, noteOff, uint64(len(noteData)), 0, 0, 4, 0)
	shstrNameIdx := len(".note.stapsdt\x00") + 1
	writeShdr(2, uint32(shstrNameIdx), 3 /*SHT_STRTAB*/, 0, 0, shstrDataOff, uint64(len(shstrNames)), 0, 0, 1, 0)

	tmp := filepath.Join(t.TempDir(), "test_edge.elf")
	if err := os.WriteFile(tmp, buf, 0600); err != nil {
		t.Fatalf("write edge ELF: %v", err)
	}
	return tmp
}

// TestScan_BoundsOverflow covers the `break` at scanner.go when
// offset+namePad+descPad > len(data).
func TestScan_BoundsOverflow(t *testing.T) {
	// 12-byte header claiming nameLen=256, descLen=256 but section is only 12 bytes.
	noteData := make([]byte, 12)
	le := binary.LittleEndian
	le.PutUint32(noteData[0:], 256) // nameLen
	le.PutUint32(noteData[4:], 256) // descLen
	le.PutUint32(noteData[8:], 3)   // noteType = NT_STAPSDT

	path := buildELFWithNoteData(t, noteData)
	probes, err := usdt.Scan(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(probes) != 0 {
		t.Errorf("expected 0 probes for bounds overflow, got %d", len(probes))
	}
}

// TestScan_WrongNoteType covers the `continue` when noteType != 3.
func TestScan_WrongNoteType(t *testing.T) {
	// Valid structure but noteType=1 (not NT_STAPSDT=3).
	desc := make([]byte, 24)
	noteData := buildNoteEntry(1, "stapsdt", desc)

	path := buildELFWithNoteData(t, noteData)
	probes, err := usdt.Scan(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(probes) != 0 {
		t.Errorf("expected 0 probes for wrong noteType, got %d", len(probes))
	}
}

// TestScan_WrongNoteName covers the `continue` when rawName != "stapsdt".
func TestScan_WrongNoteName(t *testing.T) {
	desc := make([]byte, 24)
	noteData := buildNoteEntry(3, "wrongname", desc)

	path := buildELFWithNoteData(t, noteData)
	probes, err := usdt.Scan(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(probes) != 0 {
		t.Errorf("expected 0 probes for wrong note name, got %d", len(probes))
	}
}

// TestScan_ShortDescriptor covers the `continue` when len(desc) < 24.
func TestScan_ShortDescriptor(t *testing.T) {
	desc := make([]byte, 8) // only 8 bytes, need >= 24
	noteData := buildNoteEntry(3, "stapsdt", desc)

	path := buildELFWithNoteData(t, noteData)
	probes, err := usdt.Scan(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(probes) != 0 {
		t.Errorf("expected 0 probes for short descriptor, got %d", len(probes))
	}
}

// TestScan_ProviderCstringFail covers the `continue` when provider has no null terminator.
func TestScan_ProviderCstringFail(t *testing.T) {
	// desc = 24 zero bytes (pc/base/semaphore) + 4 bytes with no null terminator.
	desc := make([]byte, 28)
	desc[24] = 'a'
	desc[25] = 'b'
	desc[26] = 'c'
	desc[27] = 'd'
	noteData := buildNoteEntry(3, "stapsdt", desc)

	path := buildELFWithNoteData(t, noteData)
	probes, err := usdt.Scan(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(probes) != 0 {
		t.Errorf("expected 0 probes for provider cstring failure, got %d", len(probes))
	}
}

// TestScan_ProbeNameCstringFail covers the `continue` when probeName has no null terminator.
func TestScan_ProbeNameCstringFail(t *testing.T) {
	// desc = 24 zero bytes + "prov\0" + "name" (no null terminator for name).
	desc := make([]byte, 24+5+4) // 33 bytes
	copy(desc[24:], "prov\x00")  // provider OK
	copy(desc[29:], "name")      // probeName without null terminator
	noteData := buildNoteEntry(3, "stapsdt", desc)

	path := buildELFWithNoteData(t, noteData)
	probes, err := usdt.Scan(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(probes) != 0 {
		t.Errorf("expected 0 probes for probeName cstring failure, got %d", len(probes))
	}
}
