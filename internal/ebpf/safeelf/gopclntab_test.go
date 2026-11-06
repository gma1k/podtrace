package safeelf

import (
	"debug/elf"
	"encoding/binary"
	"math"
	"os"
	"testing"
)

func pclnHeaderWithFileTable(order binary.ByteOrder, magic uint32, ptrSize byte, nfunc, nfiletab uint64, size int) []byte {
	data := make([]byte, size)
	order.PutUint32(data, magic)
	data[6] = 1
	data[7] = ptrSize
	put := func(word int, v uint64) {
		at := 8 + word*int(ptrSize)
		if ptrSize == 8 {
			order.PutUint64(data[at:], v)
		} else {
			order.PutUint32(data[at:], uint32(v&math.MaxUint32))
		}
	}
	put(0, nfunc)
	put(1, nfiletab)
	for word := 2; word < 8; word++ {
		put(word, 0x100)
	}
	return data
}

func go12PCLNWithFileTable(nfiletab uint32, fileOff uint32, size int) []byte {
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data, Go12PCLNTabMagic)
	data[6] = 1
	data[7] = 8
	binary.LittleEndian.PutUint64(data[8:], 1)
	binary.LittleEndian.PutUint32(data[16+3*8:], fileOff)
	if int(fileOff)+4 <= size {
		binary.LittleEndian.PutUint32(data[fileOff:], nfiletab)
	}
	return data
}

func TestAPclntabClaimingTooManyFileTableEntriesIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
		magic uint32
		ptr   byte
	}{
		{"go1.20 little-endian", binary.LittleEndian, Go120PCLNTabMagic, 8},
		{"go1.18 big-endian", binary.BigEndian, Go118PCLNTabMagic, 8},
		{"go1.16 32-bit", binary.LittleEndian, Go116PCLNTabMagic, 4},
	} {
		if GoPCLNTabWithinCap(pclnHeaderWithFileTable(tc.order, tc.magic, tc.ptr, 0, 0xffffffff, 4096)) {
			t.Errorf("%s: a header claiming 2^32-1 file-table entries passed", tc.name)
		}
		if GoPCLNTabWithinCap(pclnHeaderWithFileTable(tc.order, tc.magic, tc.ptr, 0, MaxGoFileTableCount+1, 4096)) {
			t.Errorf("%s: a header one over the file-table cap passed", tc.name)
		}
		if !GoPCLNTabWithinCap(pclnHeaderWithFileTable(tc.order, tc.magic, tc.ptr, 1000, 7341, 4096)) {
			t.Errorf("%s: a header with a cilium-sized file table was rejected", tc.name)
		}
	}
}

func TestAGo12PclntabClaimingTooManyFileTableEntriesIsRejected(t *testing.T) {
	if GoPCLNTabWithinCap(go12PCLNWithFileTable(0xffffffff, 64, 4096)) {
		t.Error("a Go 1.2 header claiming 2^32-1 file-table entries passed")
	}
	if !GoPCLNTabWithinCap(go12PCLNWithFileTable(5000, 64, 4096)) {
		t.Error("a Go 1.2 header with a realistic file table was rejected")
	}
	if !GoPCLNTabWithinCap(go12PCLNWithFileTable(0xffffffff, 1<<20, 4096)) {
		t.Error("a Go 1.2 file table outside the section was rejected here instead of by gosym")
	}
}

func TestTheFileTableCountIsReadAsTheUint32GosymUses(t *testing.T) {
	if !GoPCLNTabWithinCap(pclnHeaderWithFileTable(binary.LittleEndian, Go120PCLNTabMagic, 8, 0, 1<<32|5, 4096)) {
		t.Error("a 64-bit word gosym truncates to 5 file-table entries was rejected")
	}
}

func TestAPclntabHeaderTooShortForItsFileTableIsLeftToGosym(t *testing.T) {
	data := pclnHeaderWithFileTable(binary.LittleEndian, Go120PCLNTabMagic, 8, 0, 0xffffffff, 4096)[:16]
	if !GoPCLNTabWithinCap(data) {
		t.Error("a header with no file-table word was rejected here instead of by gosym")
	}
}

func TestTheTestBinaryPclntabIsWithinCap(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := elf.Open(exe)
	if err != nil {
		t.Skipf("test executable is not ELF: %v", err)
	}
	defer func() { _ = f.Close() }()
	data, err := SectionData(f.Section(".gopclntab"))
	if err != nil || len(data) == 0 {
		t.Skip("test executable has no .gopclntab")
	}
	if !GoPCLNTabWithinCap(data) {
		t.Error("a real Go binary's pclntab was rejected")
	}
}
