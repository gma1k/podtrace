package probes

import (
	"io/fs"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type fileID struct {
	ino     uint64
	size    int64
	mtimeNs int64
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
	return fileID{ino: st.Ino, size: fi.Size(), mtimeNs: fi.ModTime().UnixNano()}, true
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
	link link.Link
	refs int
}

type uprobeRegistry struct {
	mu    sync.Mutex
	sites map[uprobeSite]*sharedUprobe
}

var sharedUprobes = &uprobeRegistry{sites: map[uprobeSite]*sharedUprobe{}}

// acquire returns a handle on the link at site, attaching it with attach when
// there is none yet.
func (r *uprobeRegistry) acquire(site uprobeSite, attach func() (link.Link, error)) (link.Link, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sites[site]
	if !ok {
		l, err := attach()
		if err != nil {
			return nil, err
		}
		s = &sharedUprobe{link: l}
		r.sites[site] = s
	}
	s.refs++
	return &uprobeHandle{Link: s.link, site: site, reg: r}, nil
}

// release drops one handle's reference, closing the link with the last one.
func (r *uprobeRegistry) release(site uprobeSite) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sites[site]
	if !ok {
		return nil
	}
	s.refs--
	if s.refs > 0 {
		return nil
	}
	delete(r.sites, site)
	return s.link.Close()
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

// executable is link.Executable with its uprobes shared per file.
type executable struct {
	*link.Executable
	id     fileID
	shared bool
}

// openExecutable opens a file for uprobes that are shared with every other
// holder attaching the same program to the same place in the same file.
func openExecutable(path string) (*executable, error) {
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}
	id, ok := statFileID(path)
	return &executable{Executable: exe, id: id, shared: ok}, nil
}

// Uprobe attaches prog at the entry of symbol, or returns a handle on the
// identical uprobe already attached there.
func (e *executable) Uprobe(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	return e.attach(symbol, prog, opts, false)
}

// Uretprobe is Uprobe for a return probe.
func (e *executable) Uretprobe(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	return e.attach(symbol, prog, opts, true)
}

func (e *executable) attach(symbol string, prog *ebpf.Program, opts *link.UprobeOptions, ret bool) (link.Link, error) {
	attach := func() (link.Link, error) {
		if ret {
			return e.Executable.Uretprobe(symbol, prog, opts)
		}
		return e.Executable.Uprobe(symbol, prog, opts)
	}
	if !e.shared {
		return attach()
	}
	site := uprobeSite{file: e.id, symbol: symbol, prog: prog, ret: ret}
	if opts != nil {
		site.opts = *opts
	}
	return sharedUprobes.acquire(site, attach)
}
