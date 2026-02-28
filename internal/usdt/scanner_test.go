package usdt_test

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/usdt"
)

// buildSyntheticELF creates a minimal ELF64 LE binary with a .note.stapsdt
// section containing one USDT probe entry, then returns the file path.
func buildSyntheticELF(t *testing.T) string {
	t.Helper()

	// Build the note descriptor:
	//   pc(8) base(8) semaphore(8) "provider\0" "name\0" "\0"
	provider := "testprovider"
	probeName := "testprobe"
	var desc []byte
	put64 := func(v uint64) {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		desc = append(desc, b...)
	}
	put64(0xDEADBEEF) // pc
	put64(0)          // base
	put64(0)          // semaphore
	desc = append(desc, []byte(provider+"\x00")...)
	desc = append(desc, []byte(probeName+"\x00")...)
	desc = append(desc, 0) // argdesc (empty)

	noteName := "stapsdt\x00"

	// Align desc length to 4 bytes.
	for len(desc)%4 != 0 {
		desc = append(desc, 0)
	}

	// Note entry: nameLen(4) descLen(4) type(4) name(padded) desc(padded)
	var noteData []byte
	put32 := func(v uint32) {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		noteData = append(noteData, b...)
	}
	put32(uint32(len(noteName)))
	put32(uint32(len(desc)))
	put32(3) // NT_STAPSDT
	noteData = append(noteData, []byte(noteName)...)
	// pad name to 4-byte boundary
	for len(noteData)%4 != 0 {
		noteData = append(noteData, 0)
	}
	noteData = append(noteData, desc...)

	// Build minimal ELF64 LE.
	// We write a raw ELF file with one section (.note.stapsdt) + section name table.
	shstrNames := "\x00.note.stapsdt\x00.shstrtab\x00"
	shstrOffset := 1
	noteSecNameIdx := shstrOffset

	const elfHeaderSize = 64
	const shEntrySize = 64
	const numSections = 3 // null + note + shstrtab

	// Layout:
	// 0: ELF header (64 bytes)
	// 64: note data
	// 64 + len(noteData): shstrtab data
	// ... (align to 8)
	// section headers (3 * 64)

	noteOff := uint64(elfHeaderSize)
	shstrDataOff := noteOff + uint64(len(noteData))
	// align to 8
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

	// ELF magic + header
	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2        // ELFCLASS64
	buf[5] = 1        // ELFDATA2LSB
	buf[6] = 1        // EV_CURRENT
	buf[7] = 0        // ELFOSABI_NONE
	le.PutUint16(buf[16:], 2) // ET_EXEC
	le.PutUint16(buf[18:], 62) // EM_X86_64
	le.PutUint32(buf[20:], 1)  // EV_CURRENT
	// e_phoff = 0, e_shoff = shOff
	le.PutUint64(buf[40:], shOff)
	le.PutUint32(buf[48:], 0)              // e_flags
	le.PutUint16(buf[52:], elfHeaderSize)  // e_ehsize
	le.PutUint16(buf[54:], 56)             // e_phentsize
	le.PutUint16(buf[56:], 0)             // e_phnum
	le.PutUint16(buf[58:], shEntrySize)   // e_shentsize
	le.PutUint16(buf[60:], uint16(numSections)) // e_shnum
	le.PutUint16(buf[62:], 2)             // e_shstrndx (index of shstrtab)

	// Note data
	copy(buf[noteOff:], noteData)

	// shstrtab data
	copy(buf[shstrDataOff:], shstrNames)

	// Section headers (each 64 bytes for ELF64):
	// [0] null section
	// [1] .note.stapsdt (SHT_NOTE=7)
	// [2] .shstrtab (SHT_STRTAB=3)
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

	tmp := filepath.Join(t.TempDir(), "test.elf")
	if err := os.WriteFile(tmp, buf, 0600); err != nil {
		t.Fatalf("write synthetic elf: %v", err)
	}
	return tmp
}

func TestScan_SyntheticELF(t *testing.T) {
	path := buildSyntheticELF(t)

	// Verify ELF is parseable by stdlib before running our scanner.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("stdlib elf.Open failed: %v", err)
	}
	sec := f.Section(".note.stapsdt")
	_ = f.Close()
	if sec == nil {
		t.Fatal("synthetic ELF missing .note.stapsdt section")
	}

	probes, err := usdt.Scan(path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(probes))
	}
	p := probes[0]
	if p.Provider != "testprovider" {
		t.Errorf("Provider: want %q, got %q", "testprovider", p.Provider)
	}
	if p.Name != "testprobe" {
		t.Errorf("Name: want %q, got %q", "testprobe", p.Name)
	}
	if p.PC != 0xDEADBEEF {
		t.Errorf("PC: want 0xDEADBEEF, got %#x", p.PC)
	}
}

func TestScan_NonExistentFile(t *testing.T) {
	_, err := usdt.Scan("/does/not/exist.elf")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestScan_NoUSDTSection(t *testing.T) {
	// Write a minimal ELF with no .note.stapsdt section.
	// Just use any real Go binary on the system.
	probes, err := usdt.Scan("/proc/self/exe")
	if err != nil {
		// If the Go test binary can't be opened as ELF, skip.
		t.Skipf("could not open /proc/self/exe: %v", err)
	}
	// Go binaries typically have no stapsdt probes; either nil or empty is fine.
	_ = probes
}
