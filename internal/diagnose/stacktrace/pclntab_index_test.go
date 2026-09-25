package stacktrace

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func gosymTable(t *testing.T, bin string) *gosym.Table {
	t.Helper()
	f, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("open %s: %v", bin, err)
	}
	defer func() { _ = f.Close() }()
	pcln, err := f.Section(".gopclntab").Data()
	if err != nil {
		t.Fatalf("pclntab: %v", err)
	}
	tbl, err := gosym.NewTable(nil, gosym.NewLineTable(pcln, f.Section(".text").Addr))
	if err != nil {
		t.Fatalf("gosym: %v", err)
	}
	return tbl
}

func TestTheLazyIndexNamesEveryFunctionExactlyAsGosymDoes(t *testing.T) {
	bin := symFixture(t)
	table := loadSymbolTable(bin)
	if table == nil || table.pcln == nil {
		t.Fatal("a Go 1.18+ binary did not get a lazy pclntab index")
	}
	if table.goTable != nil {
		t.Error("the full gosym table was built as well, which is the cost the index exists to avoid")
	}

	funcs := gosymTable(t, bin).Funcs
	if len(funcs) < 100 {
		t.Fatalf("fixture has only %d functions; too few to trust the comparison", len(funcs))
	}
	for _, fn := range funcs {
		for _, pc := range []uint64{fn.Entry, (fn.Entry + fn.End) / 2, fn.End - 1} {
			if got := table.lookup(pc); got != fn.Name {
				t.Fatalf("lookup(%#x) = %q, gosym says %q.\n\nThe index reads pclntab "+
					"itself instead of through debug/gosym, so it must agree with it on "+
					"every function, not just the ones a test happens to name.", pc, got, fn.Name)
			}
		}
	}
}

func TestLoadingATableAllocatesAFractionOfThePclntab(t *testing.T) {
	bin := symFixture(t)
	f, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pclnSize := f.Section(".gopclntab").Size
	_ = f.Close()

	loadSymbolTable(bin)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	table := loadSymbolTable(bin)
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(table)

	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > pclnSize/2 {
		t.Errorf("loading one table allocated %d bytes against a %d-byte pclntab.\n\n"+
			"Reading the whole section and building gosym's table allocated about six "+
			"times the section: 240 MiB for this repo's own binary, on every /profile "+
			"scrape. The index only needs functab, 8 bytes per function.", allocated, pclnSize)
	}
}

func TestAPureGoBinaryNeverReadsItsELFSymbols(t *testing.T) {
	bin := symFixture(t)
	table := loadSymbolTable(bin)
	fn := gosymTable(t, bin).LookupFunc("main.TargetFunction")

	for i := 0; i < 50; i++ {
		table.lookup(fn.Entry)
	}
	if table.elfLoaded {
		t.Error("the ELF symbol table was read although every lookup was inside the Go " +
			"functions; that read is the second-largest cost the index removed")
	}
}

func TestAnAddressPastTheGoFunctionsFallsBackToELFSymbols(t *testing.T) {
	bin := symFixture(t)
	table := loadSymbolTable(bin)

	past := table.pcln.textStart + table.pcln.entry(table.pcln.nfunc) + 1
	table.lookup(past)
	if !table.elfLoaded {
		t.Error("an address outside every Go function did not consult the ELF symbols; " +
			"in a cgo binary that is where the C frames live")
	}
	if table.approxBytes() <= int64(len(table.pcln.functab)) {
		t.Error("the table's size estimate ignored the ELF symbols it just read, so the " +
			"cache budget would undercount it")
	}
}

func TestALookupRefusesAFileThatIsNoLongerTheIndexedOne(t *testing.T) {
	bin := symFixture(t)
	table := loadSymbolTable(bin)
	fn := gosymTable(t, bin).LookupFunc("main.TargetFunction")

	other := filepath.Join(t.TempDir(), "other")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.WriteFile(other, data, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := table.pcln.name(bytes.NewReader(nil), fn.Entry); got != "" {
		t.Fatalf("an unreadable file produced a name: %q", got)
	}
	if got := table.lookupAt(other, fn.Entry); got == "main.TargetFunction" {
		t.Error("the index read names from a different file than the one it was built " +
			"from.\n\nOffsets only mean something in the build that produced them; a " +
			"replaced binary at the same path would be read as garbage names.")
	}
	if got := table.lookupAt(filepath.Join(t.TempDir(), "gone"), fn.Entry); got != "" {
		t.Errorf("a missing file produced a name: %q", got)
	}
}

func TestEveryResolverSharesOneTableCache(t *testing.T) {
	a, b := NewResolver(), NewResolver()
	if a.inner.symbolTables() != sharedSymbolTables || b.inner.symbolTables() != sharedSymbolTables {
		t.Error("resolvers did not share the table cache.\n\nThe continuous profiler builds " +
			"a resolver per snapshot, so a per-resolver cache reparsed every binary on " +
			"every /profile scrape.")
	}
	own := &symbolTableCache{}
	r := stackResolver{symbols: own}
	if r.symbolTables() != own {
		t.Error("an explicitly supplied cache was ignored")
	}
}

func TestTheByteBudgetEvictsButAlwaysKeepsTheNewest(t *testing.T) {
	heavy := func() *symbolTable { return &symbolTable{goBytes: 40} }
	ids := map[string]fileID{}
	for i, p := range []string{"/a", "/b", "/c"} {
		ids[p] = fileID{dev: 1, ino: uint64(i + 1)}
	}
	c := &symbolTableCache{
		limit:    10,
		maxBytes: 100,
		statID:   func(p string) (fileID, bool) { id, ok := ids[p]; return id, ok },
		load:     func(string) *symbolTable { return heavy() },
	}

	c.get("/a")
	c.get("/b")
	if got := c.len(); got != 2 {
		t.Fatalf("held %d tables within budget, want 2", got)
	}
	c.get("/c")
	if got := c.len(); got != 2 {
		t.Errorf("held %d tables of 40 bytes each under a 100-byte budget, want 2", got)
	}

	solo := &symbolTableCache{
		maxBytes: 10,
		statID:   func(p string) (fileID, bool) { id, ok := ids[p]; return id, ok },
		load:     func(string) *symbolTable { return heavy() },
	}
	solo.get("/a")
	if got := solo.len(); got != 1 {
		t.Errorf("an oversized table was not kept at all (len %d); it would be reparsed "+
			"for every frame", got)
	}
}

func TestTheDefaultBoundsApplyWhenUnset(t *testing.T) {
	ids := map[string]fileID{}
	c := &symbolTableCache{
		statID: func(p string) (fileID, bool) {
			if _, ok := ids[p]; !ok {
				ids[p] = fileID{dev: 9, ino: uint64(len(ids) + 1)}
			}
			return ids[p], true
		},
		load: func(string) *symbolTable { return &symbolTable{} },
	}
	for i := 0; i < maxCachedSymbolTables+5; i++ {
		c.get(filepath.Join("/bin", string(rune('a'+i))))
	}
	if got := c.len(); got != maxCachedSymbolTables {
		t.Errorf("held %d tables, want the default bound %d", got, maxCachedSymbolTables)
	}
}

func TestANilTableHasNoSize(t *testing.T) {
	var tbl *symbolTable
	if tbl.approxBytes() != 0 {
		t.Error("a nil table reported a size")
	}
	if tbl.lookupAt("/x", 1) != "" {
		t.Error("a nil table produced a name")
	}
}

type pclnHeader struct {
	order    binary.ByteOrder
	magic    uint32
	quantum  byte
	ptrSize  byte
	pad      [2]byte
	nfunc    uint64
	nameTab  uint64
	funcdata uint64
}

func (h pclnHeader) bytes(size int) []byte {
	buf := make([]byte, size)
	h.order.PutUint32(buf, h.magic)
	buf[4], buf[5] = h.pad[0], h.pad[1]
	buf[6], buf[7] = h.quantum, h.ptrSize
	put := func(i int, v uint64) {
		at := 8 + i*int(h.ptrSize)
		if h.ptrSize == 8 {
			h.order.PutUint64(buf[at:], v)
		} else {
			h.order.PutUint32(buf[at:], uint32(v))
		}
	}
	put(0, h.nfunc)
	put(3, h.nameTab)
	put(7, h.funcdata)
	return buf
}

func validHeader() pclnHeader {
	return pclnHeader{order: binary.LittleEndian, magic: go120PCLnTabMagic, quantum: 1,
		ptrSize: 8, nfunc: 1, nameTab: 200, funcdata: 100}
}

func syntheticPCLN(t *testing.T, h pclnHeader) []byte {
	t.Helper()
	buf := h.bytes(512)
	o := h.order
	o.PutUint32(buf[h.funcdata:], 0x10)
	o.PutUint32(buf[h.funcdata+4:], 16)
	o.PutUint32(buf[h.funcdata+8:], 0x40)
	o.PutUint32(buf[h.funcdata+16+4:], 3)
	copy(buf[h.nameTab:], "xx\x00main.f\x00")
	return buf
}

func TestASyntheticPclntabResolvesInEitherByteOrderAndWordSize(t *testing.T) {
	for _, h := range []pclnHeader{
		validHeader(),
		func() pclnHeader { h := validHeader(); h.order = binary.BigEndian; return h }(),
		func() pclnHeader { h := validHeader(); h.ptrSize = 4; h.magic = go118PCLnTabMagic; return h }(),
	} {
		data := syntheticPCLN(t, h)
		idx, ok := parsePCLNIndex(bytes.NewReader(data), 0, uint64(len(data)), 0x1000)
		if !ok {
			t.Fatalf("a well-formed header (%v, ptr %d) was rejected", h.order, h.ptrSize)
		}
		if got := idx.name(bytes.NewReader(data), 0x1020); got != "main.f" {
			t.Errorf("name = %q, want main.f (%v, ptr %d)", got, h.order, h.ptrSize)
		}
		for _, pc := range []uint64{0x0fff, 0x1000, 0x1040} {
			if got := idx.name(bytes.NewReader(data), pc); got != "" {
				t.Errorf("name(%#x) = %q outside the function range", pc, got)
			}
		}
	}
}

func TestMalformedPclntabHeadersAreLeftToGosym(t *testing.T) {
	cases := map[string]func(*pclnHeader){
		"old magic":         func(h *pclnHeader) { h.magic = 0xfffffffa },
		"nonzero padding":   func(h *pclnHeader) { h.pad[0] = 1 },
		"bad quantum":       func(h *pclnHeader) { h.quantum = 3 },
		"bad pointer size":  func(h *pclnHeader) { h.ptrSize = 2 },
		"no functions":      func(h *pclnHeader) { h.nfunc = 0 },
		"too many funcs":    func(h *pclnHeader) { h.nfunc = 1 << 40 },
		"nametab past end":  func(h *pclnHeader) { h.nameTab = 1 << 20 },
		"funcdata past end": func(h *pclnHeader) { h.funcdata = 1 << 20 },
		"functab overruns":  func(h *pclnHeader) { h.funcdata = 505 },
	}
	for name, mutate := range cases {
		h := validHeader()
		mutate(&h)
		size := 512
		if h.ptrSize != 4 && h.ptrSize != 8 {
			h.ptrSize = 8
			data := h.bytes(size)
			data[7] = 2
			if _, ok := parsePCLNIndex(bytes.NewReader(data), 0, uint64(size), 0); ok {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		data := h.bytes(size)
		if _, ok := parsePCLNIndex(bytes.NewReader(data), 0, uint64(size), 0); ok {
			t.Errorf("%s: a malformed header was accepted; its offsets would be read as "+
				"function names", name)
		}
	}
}

func TestATruncatedPclntabIsRejected(t *testing.T) {
	for _, n := range []int{4, 12} {
		data := validHeader().bytes(512)[:n]
		if _, ok := parsePCLNIndex(bytes.NewReader(data), 0, 512, 0); ok {
			t.Errorf("a %d-byte pclntab was accepted", n)
		}
	}
	data := syntheticPCLN(t, validHeader())
	if _, ok := parsePCLNIndex(bytes.NewReader(data[:110]), 0, uint64(len(data)), 0); ok {
		t.Error("a pclntab whose functab cannot be read was accepted")
	}
}

type failAfter struct {
	data []byte
	ok   int
}

func (f *failAfter) ReadAt(p []byte, off int64) (int, error) {
	if f.ok == 0 {
		return 0, errors.New("read failed")
	}
	f.ok--
	return bytes.NewReader(f.data).ReadAt(p, off)
}

func TestANameReadThatFailsOrRunsOffTheSectionYieldsNothing(t *testing.T) {
	data := syntheticPCLN(t, validHeader())
	idx, ok := parsePCLNIndex(bytes.NewReader(data), 0, uint64(len(data)), 0x1000)
	if !ok {
		t.Fatal("setup")
	}

	if got := idx.name(&failAfter{data: data, ok: 1}, 0x1020); got != "" {
		t.Errorf("a failed name read produced %q", got)
	}

	bad := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(bad[100+16+4:], 1<<20)
	if got := idx.name(bytes.NewReader(bad), 0x1020); got != "" {
		t.Errorf("a nameOff past the section produced %q", got)
	}

	noNUL := append([]byte(nil), data...)
	for i := 203; i < len(noNUL); i++ {
		noNUL[i] = 'a'
	}
	if got := idx.name(bytes.NewReader(noNUL), 0x1020); got != "" {
		t.Errorf("a name with no terminator produced %q", got)
	}

	short := *idx
	short.funcdata = uint64(len(data)) - 20
	if got := short.name(bytes.NewReader(data), 0x1020); got != "" {
		t.Errorf("a funcdata record past the section produced %q", got)
	}
}

func TestANonELFFileGetsNoIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-elf")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := loadSymbolTable(path); got != nil {
		t.Errorf("a non-ELF file produced a table: %+v", got)
	}
}

func TestAnOlderGoBinaryFallsBackToTheFullGosymTable(t *testing.T) {
	bin := symFixture(t)
	indexPCLN = func(*elf.File) (*pclnIndex, bool) { return nil, false }
	t.Cleanup(func() { indexPCLN = loadPCLNIndex })

	table := loadSymbolTable(bin)
	if table == nil || table.goTable == nil {
		t.Fatal("with no lazy index the table did not fall back to debug/gosym; a Go " +
			"binary older than 1.18 would resolve nothing")
	}
	if table.pcln != nil {
		t.Error("the fallback table still carries an index")
	}
	if table.goBytes == 0 || table.approxBytes() < table.goBytes {
		t.Error("the fallback table's size was not counted; the byte budget exists for " +
			"exactly these tables")
	}
	fn := table.goTable.LookupFunc("main.TargetFunction")
	if got := table.lookup(fn.Entry); got != "main.TargetFunction" {
		t.Errorf("lookup through the gosym fallback = %q", got)
	}
}

type sysless struct{ os.FileInfo }

func (sysless) Sys() any { return nil }

func TestAFileWithNoStatIdentityHasNoID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if _, ok := fileIDFromInfo(sysless{info}); ok {
		t.Error("an identity was invented for a file with no stat data")
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = f.Close()
	if _, ok := fileIDOf(f); ok {
		t.Error("a closed file reported an identity")
	}
}

func TestAHeaderClaimingMillionsOfFunctionsAllocatesNothing(t *testing.T) {
	h := validHeader()
	h.nfunc = maxPCLNFunctions + 1
	data := h.bytes(512)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, ok := parsePCLNIndex(bytes.NewReader(data), 0, 1<<30, 0)
	runtime.ReadMemStats(&after)

	if ok {
		t.Fatal("a pclntab claiming more functions than any real binary has was accepted")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Errorf("rejecting it allocated %d bytes.\n\nThe executable belongs to a traced "+
			"container, so its header is untrusted: the function count must be refused "+
			"before functab is sized from it, or a crafted binary makes the agent allocate "+
			"8 bytes for every function it claims.", grew)
	}
}

func TestOversizedOrFarOffsetSectionsAreRejected(t *testing.T) {
	data := syntheticPCLN(t, validHeader())
	if _, ok := parsePCLNIndex(bytes.NewReader(data), 0, maxPCLNSectionSize+1, 0x1000); ok {
		t.Error("a section larger than any real pclntab was accepted")
	}
	if _, ok := parsePCLNIndex(bytes.NewReader(data), maxPCLNFileOffset+1, uint64(len(data)), 0x1000); ok {
		t.Error("a section offset past the cap was accepted; offsets near 2^63 wrap negative on the way to ReadAt")
	}
}
