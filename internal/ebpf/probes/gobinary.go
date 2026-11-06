package probes

import (
	"debug/elf"
	"debug/gosym"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

// Bounds on a .gopclntab. debug/gosym allocates per function and per
// file-table entry the header claims, so those counts, not the section size,
// are what keep a hostile binary from exhausting the agent's memory.
const (
	maxGoPCLNTabSize   = uint64(128) << 20
	maxGoFunctionCount = safeelf.MaxGoFunctionCount
)

type goBinary struct {
	key        goBinaryKey
	identified bool
	table      *gosym.Table
	machine    elf.Machine
	progs      []elf.ProgHeader
	textAddr   uint64
	textOffset uint64
	textSize   uint64
}

func (b *goBinary) fileOffset(vaddr uint64) (uint64, bool) {
	for _, prog := range b.progs {
		if prog.Type == elf.PT_LOAD && vaddr >= prog.Vaddr && vaddr < prog.Vaddr+prog.Memsz {
			return vaddr - prog.Vaddr + prog.Off, true
		}
	}
	return 0, false
}

// readText reads the machine code in [start, end) from the .text section of
// the executable at path, which must be the one b was built from.
func (b *goBinary) readText(path string, start, end uint64) ([]byte, bool) {
	if start < b.textAddr || end > b.textAddr+b.textSize || end <= start {
		return nil, false
	}
	f, fi, err := safeelf.OpenRegular(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	if key, ok := goBinaryKeyOf(fi); b.identified && (!ok || key != b.key) {
		return nil, false
	}
	code := make([]byte, end-start)
	if _, err := f.ReadAt(code, int64(b.textOffset+(start-b.textAddr))); err != nil {
		return nil, false
	}
	return code, true
}

const goBinaryTTL = 30 * time.Second

const maxCachedGoBinaries = 2

// goBinaryKey names a parsed executable. Unlike a uprobe's fileID it keeps
// the device: a table reused for a different file would place probes at
// offsets that are not instruction boundaries there, while a miss only costs
// a re-parse.
type goBinaryKey struct {
	fileID
	dev uint64
}

func goBinaryKeyOf(fi os.FileInfo) (goBinaryKey, bool) {
	id, ok := fileIDOf(fi)
	if !ok {
		return goBinaryKey{}, false
	}
	return goBinaryKey{fileID: id, dev: uint64(fi.Sys().(*syscall.Stat_t).Dev)}, true // #nosec G115 -- a device number; only widened.
}

type cachedGoBinary struct {
	key      goBinaryKey
	bin      *goBinary
	lastUsed time.Time
}

// goBinaryCache keeps the few most recently parsed Go executables, keyed by
// file identity, so a pass does not re-read the same pclntab per symbol.
type goBinaryCache struct {
	mu      sync.Mutex
	entries []*cachedGoBinary
	timer   *time.Timer
	now     func() time.Time
}

var goBinaries = &goBinaryCache{now: time.Now}

func (c *goBinaryCache) get(key goBinaryKey) (*goBinary, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		if e.key == key {
			e.lastUsed = c.now()
			return e.bin, true
		}
	}
	return nil, false
}

func (c *goBinaryCache) put(key goBinaryKey, bin *goBinary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxCachedGoBinaries {
		oldest := 0
		for i, e := range c.entries {
			if e.lastUsed.Before(c.entries[oldest].lastUsed) {
				oldest = i
			}
		}
		c.entries = append(c.entries[:oldest], c.entries[oldest+1:]...)
	}
	c.entries = append(c.entries, &cachedGoBinary{key: key, bin: bin, lastUsed: c.now()})
	if c.timer == nil {
		c.timer = time.AfterFunc(goBinaryTTL, c.expire)
	}
}

// expire drops the tables unused for goBinaryTTL and re-arms itself while
// any remain.
func (c *goBinaryCache) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	kept := c.entries[:0]
	for _, e := range c.entries {
		if now.Sub(e.lastUsed) < goBinaryTTL {
			kept = append(kept, e)
		}
	}
	for i := len(kept); i < len(c.entries); i++ {
		c.entries[i] = nil
	}
	c.entries = kept
	if len(c.entries) == 0 {
		c.timer = nil
		return
	}
	c.timer = time.AfterFunc(goBinaryTTL, c.expire)
}

func (c *goBinaryCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
}

// loadGoBinary returns the parsed function table of the Go executable at
// path, reusing the one already parsed for the same file.
func loadGoBinary(path string) (*goBinary, bool) {
	defer recoverParse("loadGoBinary")
	var key goBinaryKey
	cacheable := false
	if fi, err := os.Stat(path); err == nil {
		key, cacheable = goBinaryKeyOf(fi)
	}
	if cacheable {
		if bin, ok := goBinaries.get(key); ok {
			return bin, true
		}
	}
	bin, ok := parseGoBinary(path)
	if !ok {
		return nil, false
	}
	bin.key, bin.identified = key, cacheable
	if cacheable {
		goBinaries.put(key, bin)
	}
	return bin, true
}

func parseGoBinary(path string) (*goBinary, bool) {
	f, err := openELFCapped(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil || pcln.Size > maxGoPCLNTabSize || text.Type == elf.SHT_NOBITS {
		return nil, false
	}
	pclnData, err := sectionDataCapped(pcln)
	if err != nil || !safeelf.GoPCLNTabWithinCap(pclnData) {
		return nil, false
	}
	symtabData, _ := sectionDataCapped(f.Section(".gosymtab"))
	tbl, err := gosym.NewTable(symtabData, gosym.NewLineTable(pclnData, text.Addr))
	if err != nil {
		return nil, false
	}
	progs := make([]elf.ProgHeader, 0, len(f.Progs))
	for _, prog := range f.Progs {
		progs = append(progs, prog.ProgHeader)
	}
	return &goBinary{
		table:      tbl,
		machine:    f.Machine,
		progs:      progs,
		textAddr:   text.Addr,
		textOffset: text.Offset,
		textSize:   text.Size,
	}, true
}
