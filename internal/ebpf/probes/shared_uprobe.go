package probes

import (
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

type fileID struct {
	ino     uint64
	size    int64
	mtimeNs int64
	ctimeNs int64
	buildID string
}

// statFileID returns a file's identity, or false when it cannot be read, in
// which case its uprobes are not shared.
func statFileID(path string) (fileID, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, false
	}
	return fileIDOf(fi)
}

// fileIDOf is statFileID for a file already stat'ed. A FileInfo that carries
// no inode, which only a non-Unix filesystem gives, has no identity.
func fileIDOf(fi fs.FileInfo) (fileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{ino: st.Ino, size: fi.Size(), mtimeNs: fi.ModTime().UnixNano(), ctimeNs: changeTimeNs(st)}, true
}

// uprobeSite is one uprobe: a program at a place in a file.
type uprobeSite struct {
	file   fileID
	symbol string
	opts   link.UprobeOptions
	prog   *ebpf.Program
	ret    bool
}

type sharedUprobe struct {
	link     link.Link
	refs     int
	teardown func()
}

type uprobeRegistry struct {
	mu    sync.Mutex
	sites map[uprobeSite]*sharedUprobe
}

var sharedUprobes = &uprobeRegistry{sites: map[uprobeSite]*sharedUprobe{}}

type siteHooks struct {
	setup    func() error
	teardown func()
}

// acquire returns a handle on the link at site, attaching it with attach when
// there is none yet.
func (r *uprobeRegistry) acquire(site uprobeSite, attach func() (link.Link, error)) (link.Link, error) {
	return r.acquireWithHooks(site, attach, siteHooks{})
}

func (r *uprobeRegistry) acquireWithHooks(site uprobeSite, attach func() (link.Link, error), hooks siteHooks) (link.Link, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sites[site]
	if !ok {
		if hooks.setup != nil {
			if err := hooks.setup(); err != nil {
				return nil, err
			}
		}
		l, err := attach()
		if err != nil {
			if hooks.teardown != nil {
				hooks.teardown()
			}
			return nil, err
		}
		s = &sharedUprobe{link: l, teardown: hooks.teardown}
		r.sites[site] = s
	}
	s.refs++
	return &uprobeHandle{Link: s.link, site: site, reg: r}, nil
}

// release drops one handle's reference, closing the link with the last one.
//
// The close runs after the registry lock is released. Closing a uprobe link
// waits for the kernel to retire the probe, which takes milliseconds, and the
// tracer closes its links from many goroutines at once: under the lock those
// closes ran one at a time, so an agent with a few thousand uprobes outlived
// its termination grace period on every shutdown.
func (r *uprobeRegistry) release(site uprobeSite) error {
	r.mu.Lock()
	s, ok := r.sites[site]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	s.refs--
	if s.refs > 0 {
		r.mu.Unlock()
		return nil
	}
	delete(r.sites, site)
	r.mu.Unlock()

	err := s.link.Close()
	if s.teardown != nil {
		s.teardown()
	}
	return err
}

// uprobeHandle is one holder's reference on a shared uprobe link.
type uprobeHandle struct {
	link.Link
	site uprobeSite
	reg  *uprobeRegistry
	once sync.Once
}

// Close releases this holder's reference; closing a handle twice is a no-op.
func (h *uprobeHandle) Close() error {
	var err error
	h.once.Do(func() { err = h.reg.release(h.site) })
	return err
}

// unsharedLink is a link no other holder shares, with its teardown run on
// Close.
type unsharedLink struct {
	link.Link
	teardown func()
	once     sync.Once
}

func (l *unsharedLink) Close() error {
	var err error
	l.once.Do(func() {
		err = l.Link.Close()
		l.teardown()
	})
	return err
}

// errSymbolTablesTooLarge refuses a by-name attach on a file whose symbol
// tables exceed safeelf.MaxSymbolTableSize.
var errSymbolTablesTooLarge = errors.New("symbol tables too large to resolve symbols safely")

// executable is link.Executable with its uprobes shared per file.
//
// The file is held open for the executable's lifetime and handed to cilium as
// /proc/self/fd/<n>, so every later open, including cilium's lazy symbol
// parse and the kernel's own lookup at attach time, reaches the file that was
// checked here. A pod cannot swap a FIFO in under the library's name after
// the check.
type executable struct {
	*link.Executable
	file          *os.File
	id            fileID
	shared        bool
	symbolsOnce   sync.Once
	symbolsUnsafe bool
}

// The cilium calls behind an executable, replaceable so the sharing and
// lifecycle logic around them can be exercised without a kernel.
var (
	openLinkExecutable = link.OpenExecutable
	preloadSymbols     = func(exe *link.Executable) { _, _ = exe.Symbol(0) }
	attachToExecutable = func(exe *link.Executable, symbol string, prog *ebpf.Program, opts *link.UprobeOptions, ret bool) (link.Link, error) {
		if UprobeMultiEnabled() {
			symbols, multiOpts := uprobeMultiArgs(symbol, opts)
			if ret {
				return exe.UretprobeMulti(symbols, prog, multiOpts)
			}
			return exe.UprobeMulti(symbols, prog, multiOpts)
		}
		if ret {
			return exe.Uretprobe(symbol, prog, opts)
		}
		return exe.Uprobe(symbol, prog, opts)
	}
)

// openExecutable opens a file for uprobes that are shared with every other
// holder attaching the same program to the same place in the same file.
// Callers Close it once their attaches are done; links stay valid after.
//
// Everything a caller resolves for these uprobes must be parsed from Path,
// the file held open here, never from a second open of the original path: a
// process can exec another binary in between, and offsets read from that one
// would land in this one.
func openExecutable(path string) (*executable, error) {
	f, fi, err := openAttachTarget(path)
	if err != nil {
		return nil, err
	}
	exe, err := openLinkExecutable(safeelf.PinnedPath(f, path))
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	id, ok := fileIDOf(fi)
	if ok {
		id.buildID = buildIDOf(f)
	}
	return &executable{
		Executable: exe,
		file:       f,
		id:         id,
		shared:     ok,
	}, nil
}

var openWithinRoot = safeelf.OpenWithinRoot

// openAttachTarget opens path as the file to attach to. A path inside a
// process's root is resolved again within that root, so a directory the pod
// swapped for a symlink after the path was checked cannot lead the open out
// of its rootfs; the file opened is the one attached.
func openAttachTarget(path string) (*os.File, os.FileInfo, error) {
	if root, rel, ok := splitProcRoot(path); ok {
		f, fi, err := openWithinRoot(root, rel)
		if !errors.Is(err, safeelf.ErrConfinementUnsupported) {
			return f, fi, err
		}
	}
	return safeelf.OpenRegular(path)
}

// Path names the file the executable holds open, valid until Close.
func (e *executable) Path() string {
	if e == nil || e.file == nil {
		return ""
	}
	return safeelf.PinnedPath(e.file, e.file.Name())
}

// Close releases the file the executable holds open.
func (e *executable) Close() error {
	if e == nil || e.file == nil {
		return nil
	}
	return e.file.Close()
}

// buildIDOf returns the GNU build-id of the ELF f holds open, or "" for a
// file that is not ELF.
func buildIDOf(f *os.File) (buildID string) {
	defer recoverParse("buildIDOf")
	ef, err := elf.NewFile(f)
	if err != nil {
		return ""
	}
	return elfBuildID(ef)
}

// symbolTablesUnsafe reports whether the file's symbol tables are too large
// for cilium to resolve symbols in, checked on the first attach by name.
func (e *executable) symbolTablesUnsafe() bool {
	e.symbolsOnce.Do(func() {
		if e.file != nil {
			e.symbolsUnsafe = !symbolTablesWithinCap(e.file)
		}
	})
	return e.symbolsUnsafe
}

// symbolTablesWithinCap reports whether the ELF f holds open has symbol
// tables small enough for cilium to parse. A file that is not ELF passes,
// and fails in cilium as it would have.
func symbolTablesWithinCap(f *os.File) (within bool) {
	defer recoverParse("symbolTablesWithinCap")
	ef, err := elf.NewFile(f)
	if err != nil {
		return true
	}
	return safeelf.SymbolTablesWithinCap(ef)
}

// Uprobe attaches prog at the entry of symbol, or returns a handle on the
// identical uprobe already attached there.
func (e *executable) Uprobe(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	return e.attach(symbol, prog, opts, false, siteHooks{})
}

// Uretprobe is Uprobe for a return probe.
func (e *executable) Uretprobe(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	return e.attach(symbol, prog, opts, true, siteHooks{})
}

// uprobeWithHooks is Uprobe with hooks run around the one real attach of the
// site, and on its final release.
func (e *executable) uprobeWithHooks(prog *ebpf.Program, opts *link.UprobeOptions, hooks siteHooks) (link.Link, error) {
	return e.attach("", prog, opts, false, hooks)
}

func (e *executable) attach(symbol string, prog *ebpf.Program, opts *link.UprobeOptions, ret bool, hooks siteHooks) (link.Link, error) {
	if symbol != "" && (opts == nil || opts.Address == 0) {
		if e.symbolTablesUnsafe() {
			return nil, fmt.Errorf("symbol %s: %w", symbol, errSymbolTablesTooLarge)
		}
		// Parse the symbol tables now, outside the registry lock that
		// every other attach and detach on the node waits on.
		preloadSymbols(e.Executable)
	}
	attach := func() (link.Link, error) {
		return attachToExecutable(e.Executable, symbol, prog, opts, ret)
	}
	if !e.shared {
		if hooks.setup != nil {
			if err := hooks.setup(); err != nil {
				return nil, err
			}
		}
		l, err := attach()
		if hooks.teardown == nil {
			return l, err
		}
		if err != nil {
			hooks.teardown()
			return nil, err
		}
		return &unsharedLink{Link: l, teardown: hooks.teardown}, nil
	}
	site := uprobeSite{file: e.id, symbol: symbol, prog: prog, ret: ret}
	if opts != nil {
		site.opts = *opts
	}
	return sharedUprobes.acquireWithHooks(site, attach, hooks)
}
