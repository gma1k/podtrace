package probes

import (
	"fmt"
	"hash/maphash"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// Struct layouts, the field offsets a uprobe reads from a traced binary's
// memory, belong to the binary, so they are published per binary: every
// uprobe site that reads one carries the binary's layout cookie, and the BPF
// side looks the layout up by bpf_get_attach_cookie. Every process running
// the binary, whether a fork, a restart or another worker, then reads the
// right layout with nothing to publish per process, and an entry lives
// exactly as long as the sites that read it.

// layoutMap is the part of an ebpf.Map a layout table writes.
type layoutMap interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

// layoutEntry is one layout to publish under a cookie. A nil value
// publishes nothing, and the BPF side falls back as for a binary without
// DWARF.
type layoutEntry struct {
	m     layoutMap
	value any
}

type layoutUse struct {
	m      layoutMap
	cookie uint64
}

// layoutTable counts the uprobe sites reading each published layout, so an
// entry is deleted with the last site that reads it and never while one
// still does.
type layoutTable struct {
	mu    sync.Mutex
	users map[layoutUse]int
}

var goLayouts = &layoutTable{users: map[layoutUse]int{}}

// hold publishes entries under cookie for one site and returns what it
// published, for release.
func (t *layoutTable) hold(cookie uint64, entries []layoutEntry) []layoutUse {
	t.mu.Lock()
	defer t.mu.Unlock()
	var held []layoutUse
	for _, e := range entries {
		if e.m == nil || e.value == nil {
			continue
		}
		use := layoutUse{m: e.m, cookie: cookie}
		if t.users[use] == 0 {
			if err := e.m.Update(cookie, e.value, ebpf.UpdateAny); err != nil {
				logger.Debug("Go struct layout not published; its probes fall back to defaults",
					zap.Uint64("cookie", cookie), zap.Error(err))
				continue
			}
		}
		t.users[use]++
		held = append(held, use)
	}
	return held
}

func (t *layoutTable) release(held []layoutUse) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, use := range held {
		t.users[use]--
		if t.users[use] > 0 {
			continue
		}
		delete(t.users, use)
		_ = use.m.Delete(use.cookie)
	}
}

// siteLayout is the layout state a binary's layout-reading uprobe sites
// carry.
type siteLayout struct {
	cookie  uint64
	entries []layoutEntry
}

// hooks returns the hooks for one site: they publish the layout when the
// site is first attached and delete it when the site is last released.
func (l *siteLayout) hooks() siteHooks {
	var held []layoutUse
	return siteHooks{
		setup: func() error {
			held = goLayouts.hold(l.cookie, l.entries)
			return nil
		},
		teardown: func() {
			goLayouts.release(held)
			held = nil
		},
	}
}

var (
	layoutCookieSeed = maphash.MakeSeed()
	layoutCookieSeq  atomic.Uint64
)

// layoutCookie names exe's layout. It is derived from the file's identity
// with a seed private to this agent, so the sites of one binary in any
// container share a cookie and a pod cannot pick a name that collides with
// another binary's. A file without an identity gets a cookie of its own.
func layoutCookie(exe *executable) uint64 {
	if !exe.shared {
		return layoutCookieSeq.Add(1) | 1<<63
	}
	var h maphash.Hash
	h.SetSeed(layoutCookieSeed)
	_, _ = fmt.Fprintf(&h, "%d:%d:%d:%d:%s", exe.id.ino, exe.id.size, exe.id.mtimeNs, exe.id.ctimeNs, exe.id.buildID)
	return h.Sum64()&^(1<<63) | 1
}

// newSiteLayout returns the layout state for exe's sites, or nil when there
// is nothing to publish.
func newSiteLayout(exe *executable, entries ...layoutEntry) *siteLayout {
	if exe == nil {
		return nil
	}
	for _, e := range entries {
		if e.m != nil && e.value != nil {
			return &siteLayout{cookie: layoutCookie(exe), entries: entries}
		}
	}
	return nil
}

// layoutMapOf returns the collection's map name as a layoutMap, or nil when
// it was not loaded.
var layoutMapOf = func(coll *ebpf.Collection, name string) layoutMap {
	if m := coll.Maps[name]; m != nil {
		return m
	}
	return nil
}

// uprobeAt attaches prog at symbol or at the file offset addr. With a layout
// the site carries its cookie and publishes the layout for as long as it is
// attached.
func uprobeAt(exe uprobeTarget, symbol string, prog *ebpf.Program, addr uint64, layout *siteLayout) (link.Link, error) {
	var opts *link.UprobeOptions
	if addr != 0 {
		opts = &link.UprobeOptions{Address: addr}
	}
	if layout == nil {
		return exe.Uprobe(symbol, prog, opts)
	}
	if opts == nil {
		opts = &link.UprobeOptions{}
	}
	opts.Cookie = layout.cookie
	if e, ok := exe.(*executable); ok {
		return e.attach(symbol, prog, opts, false, layout.hooks())
	}
	return exe.Uprobe(symbol, prog, opts)
}
