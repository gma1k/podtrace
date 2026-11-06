package probes

import (
	"encoding/binary"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

func pclnHeader(order binary.ByteOrder, magic uint32, ptrSize byte, nfunc uint64, size int) []byte {
	data := make([]byte, size)
	order.PutUint32(data, magic)
	data[6] = 1
	data[7] = ptrSize
	if ptrSize == 8 {
		order.PutUint64(data[8:], nfunc)
	} else {
		order.PutUint32(data[8:], uint32(nfunc))
	}
	return data
}

func TestAPclntabClaimingTooManyFunctionsIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
		magic uint32
		ptr   byte
	}{
		{"go1.20 little-endian", binary.LittleEndian, safeelf.Go120PCLNTabMagic, 8},
		{"go1.18 big-endian", binary.BigEndian, safeelf.Go118PCLNTabMagic, 8},
		{"go1.16 32-bit", binary.LittleEndian, safeelf.Go116PCLNTabMagic, 4},
		{"go1.2", binary.LittleEndian, safeelf.Go12PCLNTabMagic, 8},
	} {
		if safeelf.GoPCLNTabWithinCap(pclnHeader(tc.order, tc.magic, tc.ptr, maxGoFunctionCount+1, 64)) {
			t.Errorf("%s: a header claiming %d functions passed", tc.name, maxGoFunctionCount+1)
		}
		if !safeelf.GoPCLNTabWithinCap(pclnHeader(tc.order, tc.magic, tc.ptr, 1000, 64)) {
			t.Errorf("%s: a header claiming 1000 functions was rejected", tc.name)
		}
	}
}

func TestAPclntabHeaderGosymWouldRejectIsLeftToGosym(t *testing.T) {
	for _, data := range [][]byte{nil, {1, 2, 3}, pclnHeader(binary.LittleEndian, 0x12345678, 8, 1<<40, 64)} {
		if !safeelf.GoPCLNTabWithinCap(data) {
			t.Errorf("header % x was rejected here instead of by gosym", data)
		}
	}
}

func TestAHostileGopclntabDoesNotDriveAHugeAllocation(t *testing.T) {
	const size = 9 << 20
	nfunc := uint64(size/8 - 1)
	path := filepath.Join(t.TempDir(), "hostile")
	writeTestELF(t, path, []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 64)},
		{name: ".gopclntab", typ: shtProgbits, flags: shfAlloc, data: pclnHeader(binary.LittleEndian, safeelf.Go120PCLNTabMagic, 8, nfunc, size)},
	})
	goBinaries.reset()
	t.Cleanup(goBinaries.reset)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, ok := goSymbolFileOffset(path, "main.main")
	runtime.ReadMemStats(&after)

	if ok {
		t.Fatal("resolved a symbol from a pclntab with no real functions")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("allocated %d MiB parsing a %d MiB pclntab that claims %d functions; the agent's whole limit is 1 GiB",
			grew>>20, size>>20, nfunc)
	}
}

func hostileFileTablePCLN(size int) []byte {
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data, safeelf.Go120PCLNTabMagic)
	data[6] = 1
	data[7] = 8
	binary.LittleEndian.PutUint64(data[16:], 0xffffffff)
	for word := 2; word < 8; word++ {
		binary.LittleEndian.PutUint64(data[8+word*8:], 0x100)
	}
	return data
}

func TestAHostileGopclntabFileTableDoesNotDriveAHugeAllocation(t *testing.T) {
	const size = 8 << 20
	path := filepath.Join(t.TempDir(), "hostile-filetab")
	writeTestELF(t, path, []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 64)},
		{name: ".gopclntab", typ: shtProgbits, flags: shfAlloc, data: hostileFileTablePCLN(size)},
	})
	goBinaries.reset()
	t.Cleanup(goBinaries.reset)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, ok := goSymbolFileOffset(path, "main.main")
	runtime.ReadMemStats(&after)

	if ok {
		t.Fatal("resolved a symbol from a pclntab with no real functions")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("allocated %d MiB parsing a %d MiB pclntab whose file table claims 2^32-1 entries",
			grew>>20, size>>20)
	}
}
