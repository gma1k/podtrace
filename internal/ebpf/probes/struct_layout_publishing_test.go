package probes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

type recordingLayoutMap struct {
	values    map[uint64]any
	updates   int
	updateErr error
}

func (m *recordingLayoutMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updates++
	m.values[key.(uint64)] = value
	return nil
}

func (m *recordingLayoutMap) Delete(key any) error {
	delete(m.values, key.(uint64))
	return nil
}

func newRecordingLayoutMap() *recordingLayoutMap {
	return &recordingLayoutMap{values: map[uint64]any{}}
}

func withLayoutMaps(t *testing.T, names ...string) map[string]*recordingLayoutMap {
	t.Helper()
	maps := map[string]*recordingLayoutMap{}
	for _, n := range names {
		maps[n] = newRecordingLayoutMap()
	}
	orig, origTable := layoutMapOf, goLayouts
	layoutMapOf = func(_ *ebpf.Collection, name string) layoutMap {
		if m, ok := maps[name]; ok {
			return m
		}
		return nil
	}
	goLayouts = &layoutTable{users: map[layoutUse]int{}}
	t.Cleanup(func() { layoutMapOf, goLayouts = orig, origTable })
	return maps
}

func TestALayoutLivesFromItsFirstSiteToItsLast(t *testing.T) {
	m := newRecordingLayoutMap()
	table := &layoutTable{users: map[layoutUse]int{}}
	entries := []layoutEntry{{m: m, value: "first"}}
	a := table.hold(7, entries)
	b := table.hold(7, []layoutEntry{{m: m, value: "second"}})
	if m.updates != 1 || m.values[7] != "first" {
		t.Fatalf("map = %v after %d updates, want the first site's layout written once", m.values, m.updates)
	}
	table.release(a)
	if _, ok := m.values[7]; !ok {
		t.Fatal("the layout was deleted while a site still reads it")
	}
	table.release(b)
	if _, ok := m.values[7]; ok || len(table.users) != 0 {
		t.Fatalf("map = %v users = %v after the last site, want both empty", m.values, table.users)
	}
}

func TestALayoutThatCannotBePublishedIsNotReleasedForItsSite(t *testing.T) {
	m := newRecordingLayoutMap()
	table := &layoutTable{users: map[layoutUse]int{}}
	m.updateErr = errors.New("map full")
	failed := table.hold(7, []layoutEntry{{m: m, value: "x"}})
	if len(failed) != 0 {
		t.Fatalf("hold = %v for a layout that was never written", failed)
	}
	m.updateErr = nil
	held := table.hold(7, []layoutEntry{{m: m, value: "x"}})
	table.release(failed)
	if _, ok := m.values[7]; !ok {
		t.Fatal("releasing a site that published nothing deleted another site's layout")
	}
	table.release(held)
	if _, ok := m.values[7]; ok {
		t.Fatal("the layout outlived its last site")
	}
}

func TestALayoutWithoutAMapOrAValuePublishesNothing(t *testing.T) {
	m := newRecordingLayoutMap()
	table := &layoutTable{users: map[layoutUse]int{}}
	if held := table.hold(7, []layoutEntry{{m: nil, value: "x"}, {m: m, value: nil}}); len(held) != 0 || m.updates != 0 {
		t.Fatalf("hold = %v with %d updates, want nothing published", held, m.updates)
	}
}

func TestLayoutCookiesFollowTheFileIdentity(t *testing.T) {
	id := fileID{ino: 1, size: 2, mtimeNs: 3, ctimeNs: 4, buildID: "ab"}
	a := layoutCookie(&executable{id: id, shared: true})
	b := layoutCookie(&executable{id: id, shared: true})
	other := id
	other.ctimeNs++
	c := layoutCookie(&executable{id: other, shared: true})
	if a != b {
		t.Errorf("one file got cookies %x and %x", a, b)
	}
	if a == c {
		t.Errorf("a copied-up file shares cookie %x with its original", a)
	}
	if a == 0 || a&(1<<63) != 0 {
		t.Errorf("shared cookie %x must be non-zero with the top bit clear", a)
	}
	u1, u2 := layoutCookie(&executable{}), layoutCookie(&executable{})
	if u1 == u2 || u1&(1<<63) == 0 || u2&(1<<63) == 0 {
		t.Errorf("unshared cookies %x %x must be distinct with the top bit set", u1, u2)
	}
}

func TestASiteLayoutNeedsAnExecutableAndSomethingToPublish(t *testing.T) {
	m := newRecordingLayoutMap()
	exe := &executable{id: fileID{ino: 9}, shared: true}
	if l := newSiteLayout(nil, layoutEntry{m: m, value: 1}); l != nil {
		t.Errorf("newSiteLayout(nil) = %+v", l)
	}
	if l := newSiteLayout(exe, layoutEntry{m: m}, layoutEntry{value: 1}); l != nil {
		t.Errorf("newSiteLayout with nothing to publish = %+v", l)
	}
	if l := newSiteLayout(exe, layoutEntry{m: m, value: 1}); l == nil || l.cookie != layoutCookie(exe) {
		t.Errorf("newSiteLayout = %+v, want the executable's cookie", l)
	}
}

func goLayoutProc(t *testing.T, pids ...uint32) {
	t.Helper()
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	bin := filepath.Join(base, "server")
	writeTestELF(t, bin, rustLikeSections("main.main"))
	for _, pid := range pids {
		dir := filepath.Join(base, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(bin, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUprobeAtCarriesTheLayoutCookieForTheSiteLifetime(t *testing.T) {
	goLayoutProc(t, 1)
	f := installFakeAttacher(t, nil)
	maps := withLayoutMaps(t, "m")
	exe, err := openExecutable(filepath.Join(config.ProcBasePath, "1", "exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	layout := newSiteLayout(exe, layoutEntry{m: maps["m"], value: "layout"})
	prog := &ebpf.Program{}
	first, err := uprobeAt(exe, "", prog, 0x10, layout)
	if err != nil {
		t.Fatal(err)
	}
	second, err := uprobeAt(exe, "", prog, 0x10, layout)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || f.calls[0].cookie != layout.cookie || f.calls[0].addr != 0x10 {
		t.Fatalf("calls = %+v, want one shared site carrying cookie %x", f.calls, layout.cookie)
	}
	if maps["m"].values[layout.cookie] != "layout" || maps["m"].updates != 1 {
		t.Fatalf("map = %v, want the layout published once under the cookie", maps["m"].values)
	}
	_ = first.Close()
	if _, ok := maps["m"].values[layout.cookie]; !ok {
		t.Fatal("the layout went with the first handle while the site is still attached")
	}
	_ = second.Close()
	if _, ok := maps["m"].values[layout.cookie]; ok {
		t.Fatal("the layout outlived the site")
	}
}

func TestUprobeAtWithoutALayoutKeepsPlainOptions(t *testing.T) {
	goLayoutProc(t, 1)
	f := installFakeAttacher(t, nil)
	exe, err := openExecutable(filepath.Join(config.ProcBasePath, "1", "exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	prog := &ebpf.Program{}
	if _, err := uprobeAt(exe, "main.main", prog, 0, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := uprobeAt(exe, "", prog, 0x20, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0].symbol != "main.main" || f.calls[0].cookie != 0 || f.calls[1].addr != 0x20 || f.calls[1].cookie != 0 {
		t.Fatalf("calls = %+v, want a by-name and a by-offset attach without cookies", f.calls)
	}
}

func TestUprobeAtOnAnotherTargetStillCarriesTheCookie(t *testing.T) {
	target := &scriptedTarget{}
	layout := &siteLayout{cookie: 42}
	if _, err := uprobeAt(target, "sym", &ebpf.Program{}, 0, layout); err != nil {
		t.Fatal(err)
	}
	if len(target.attached) != 1 || target.cookies[0] != 42 {
		t.Fatalf("attached %v cookies %v, want one attach with cookie 42", target.attached, target.cookies)
	}
}

func TestEveryProcessOfAGRPCBinaryReadsOneLayoutThroughTheSiteCookie(t *testing.T) {
	bin := grpcFixtureBinary(t)
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	for _, pid := range []uint32{4280, 4281} {
		dir := filepath.Join(base, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(bin, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	f := installFakeAttacher(t, nil)
	maps := withLayoutMaps(t, "grpc_go_offsets")
	coll := placeholderPrograms("uprobe_grpc_go_write_header", "uprobe_grpc_go_server_headers", "uprobe_grpc_go_client_headers")

	first := AttachGoGRPCProbes(coll, 4280)
	second := AttachGoGRPCProbes(coll, 4281)
	if len(first) != 3 || len(second) != 3 || len(f.calls) != 3 {
		t.Fatalf("links %d+%d, calls %d: want three sites shared by both processes", len(first), len(second), len(f.calls))
	}
	cookie := f.calls[0].cookie
	for _, c := range f.calls {
		if c.cookie == 0 || c.cookie != cookie {
			t.Fatalf("calls = %+v, want every site to carry one non-zero cookie", f.calls)
		}
	}
	want, ok := resolveGRPCGoFieldOffsets(bin, 0)
	if !ok || maps["grpc_go_offsets"].values[cookie] != want {
		t.Fatalf("published %v, want %+v under cookie %x", maps["grpc_go_offsets"].values, want, cookie)
	}
	for _, l := range append(first, second...) {
		_ = l.Close()
	}
	if len(maps["grpc_go_offsets"].values) != 0 {
		t.Fatalf("layouts %v outlived every site", maps["grpc_go_offsets"].values)
	}
}

func TestAGRPCBinaryWithoutTheTransportPublishesNoLayout(t *testing.T) {
	goLayoutProc(t, 4282)
	f := installFakeAttacher(t, nil)
	maps := withLayoutMaps(t, "grpc_go_offsets")
	coll := placeholderPrograms("uprobe_grpc_go_write_header", "uprobe_grpc_go_server_headers", "uprobe_grpc_go_client_headers")
	_ = AttachGoGRPCProbes(coll, 4282)
	for _, c := range f.calls {
		if c.cookie != 0 {
			t.Fatalf("calls = %+v, want no cookie without grpc-go", f.calls)
		}
	}
	if len(maps["grpc_go_offsets"].values) != 0 {
		t.Fatalf("published %v for a binary without grpc-go", maps["grpc_go_offsets"].values)
	}
}

func TestThePoolWaitEntryPublishesTheDBLayoutUnderItsCookie(t *testing.T) {
	plain, _ := poolFixtures(t)
	f := installFakeAttacher(t, nil)
	maps := withLayoutMaps(t, "pool_offsets")
	orig := goFuncReturns
	t.Cleanup(func() { goFuncReturns = orig })
	goFuncReturns = func(string, string) (uint64, []uint64, bool) { return 100, []uint64{110}, true }

	links := attachGoAcquireProbes(placeholderPrograms("uprobe_go_db_conn", "uprobe_go_db_conn_ret"), plain, 1)
	if len(links) != 2 || len(f.calls) != 2 {
		t.Fatalf("links=%d calls=%+v, want the entry and one return", len(links), f.calls)
	}
	entry, ret := f.calls[0], f.calls[1]
	want, ok := resolvePoolFieldOffsets(plain, 0)
	if !ok {
		t.Fatal("fixture offsets did not resolve")
	}
	published := maps["pool_offsets"].values[entry.cookie]
	if entry.cookie == 0 || published != (struct{ NumOpen, MaxOpen, FreeConn uint32 }{want.NumOpen, want.MaxOpen, want.FreeConn}) {
		t.Fatalf("entry cookie %x published %v, want %+v", entry.cookie, published, want)
	}
	if ret.cookie != 0 {
		t.Errorf("the return site carries cookie %x but reads no layout", ret.cookie)
	}
	for _, l := range links {
		_ = l.Close()
	}
	if len(maps["pool_offsets"].values) != 0 {
		t.Fatalf("pool layout %v outlived the entry site", maps["pool_offsets"].values)
	}
}

func TestHTTP3SitesThatReadLayoutsShareTheBinarysCookie(t *testing.T) {
	goLayoutProc(t, 4283, 4284)
	f := installFakeAttacher(t, nil)
	maps := withLayoutMaps(t, "h3_offsets", "h3_peer_paths_map")
	orig := goFuncReturns
	t.Cleanup(func() { goFuncReturns = orig })
	goFuncReturns = func(_, sym string) (uint64, []uint64, bool) {
		switch sym {
		case "github.com/quic-go/quic-go/http3.(*SingleDestinationRoundTripper).RoundTrip":
			return 0x100, []uint64{0x110}, true
		case "github.com/quic-go/quic-go/http3.requestFromHeaders":
			return 0x300, []uint64{0x310}, true
		case "github.com/quic-go/quic-go/http3.parseHeaders":
			return 0x200, []uint64{0x210}, true
		}
		return 0, nil, false
	}
	coll := placeholderPrograms("uprobe_h3_roundtrip", "uprobe_h3_roundtrip_ret", "uprobe_h3_req_from_headers_ret",
		"uprobe_h3_parse_headers", "uprobe_h3_parse_headers_ret")

	first := AttachGoHTTP3Probes(coll, 4283)
	second := AttachGoHTTP3Probes(coll, 4284)
	if len(first) != 5 || len(second) != 5 || len(f.calls) != 5 {
		t.Fatalf("links %d+%d calls %+v, want five sites shared by both processes", len(first), len(second), f.calls)
	}
	var cookie uint64
	for _, c := range f.calls {
		switch c.addr {
		case 0x100, 0x110, 0x310:
			if c.cookie == 0 || (cookie != 0 && c.cookie != cookie) {
				t.Fatalf("layout-reading site %+v, want one non-zero cookie", c)
			}
			cookie = c.cookie
		default:
			if c.cookie != 0 {
				t.Errorf("site %+v reads no layout but carries a cookie", c)
			}
		}
	}
	if maps["h3_offsets"].values[cookie] != h3DefaultOffsets {
		t.Fatalf("h3_offsets = %v, want the default offsets under %x", maps["h3_offsets"].values, cookie)
	}
	if len(maps["h3_peer_paths_map"].values) != 0 {
		t.Errorf("peer paths %v published for a binary without DWARF", maps["h3_peer_paths_map"].values)
	}
	for _, l := range append(first, second...) {
		_ = l.Close()
	}
	if len(maps["h3_offsets"].values) != 0 {
		t.Fatalf("h3 layout %v outlived its sites", maps["h3_offsets"].values)
	}
}

func TestLayoutMapOfReturnsOnlyALoadedMap(t *testing.T) {
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{"loaded": {}}}
	if layoutMapOf(coll, "loaded") == nil {
		t.Error("a loaded map was not returned")
	}
	if layoutMapOf(coll, "missing") != nil {
		t.Error("a missing map was returned as a non-nil interface")
	}
}

func grpcFixtureProc(t *testing.T, pid uint32) string {
	t.Helper()
	bin := grpcFixtureBinary(t)
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	dir := filepath.Join(base, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	return bin
}

func refuseByName(c attachCall) error {
	if c.symbol != "" {
		return errors.New("symbol not in the dynamic table")
	}
	return nil
}

func TestGRPCSitesFallingBackToPclntabOffsetsKeepTheLayoutCookie(t *testing.T) {
	grpcFixtureProc(t, 4285)
	f := installFakeAttacher(t, refuseByName)
	maps := withLayoutMaps(t, "grpc_go_offsets")
	coll := placeholderPrograms("uprobe_grpc_go_write_header", "uprobe_grpc_go_server_headers", "uprobe_grpc_go_client_headers")
	links := AttachGoGRPCProbes(coll, 4285)
	if len(links) != 3 {
		t.Fatalf("attached %d links, want all three by pclntab offset", len(links))
	}
	for _, c := range f.calls {
		if c.cookie == 0 {
			t.Fatalf("call %+v carries no layout cookie", c)
		}
	}
	if len(maps["grpc_go_offsets"].values) != 1 {
		t.Fatalf("published %v, want one layout", maps["grpc_go_offsets"].values)
	}
}

func TestAGoUprobeByNameFallsBackToItsPclntabOffsetWithTheLayoutCookie(t *testing.T) {
	bin := grpcFixtureProc(t, 4286)
	f := installFakeAttacher(t, refuseByName)
	maps := withLayoutMaps(t, "m")
	exe, err := openExecutable(filepath.Join(config.ProcBasePath, "4286", "exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	layout := newSiteLayout(exe, layoutEntry{m: maps["m"], value: 1})
	if _, ok := attachGoUprobeBySymbol(exe, bin, "main.main", &ebpf.Program{}, layout); !ok {
		t.Fatal("main.main did not attach by its pclntab offset")
	}
	last := f.calls[len(f.calls)-1]
	if last.symbol != "" || last.addr == 0 || last.cookie != layout.cookie {
		t.Fatalf("fallback attach %+v, want an offset attach carrying cookie %x", last, layout.cookie)
	}
	if _, ok := attachGoUprobeBySymbol(exe, bin, "main.nowhere", &ebpf.Program{}, layout); ok {
		t.Fatal("attached a symbol the binary does not have")
	}
}

func TestAGRPCLayoutNeedsResolvableFramerOffsets(t *testing.T) {
	withLayoutMaps(t, "grpc_go_offsets")
	bin := goFixtureBinary(t)
	exe, err := openExecutable(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	if l := grpcGoLayout(&ebpf.Collection{}, exe, bin, 1); l != nil {
		t.Fatalf("grpcGoLayout = %+v for a binary without grpc-go", l)
	}
}

func singleDestinationDWARF(b *dwarfBuilder) {
	quicServerDWARF(b, false)
	word := b.base("uintptr")
	iface := b.structType("github.com/quic-go/quic-go.Connection", member("tab", 0, word), member("data", 8, word))
	b.structType("github.com/quic-go/quic-go/http3.SingleDestinationRoundTripper", member("Connection", 16, iface))
}

func TestASingleDestinationRoundTripperPeerPathStartsAtItsConnection(t *testing.T) {
	var b dwarfBuilder
	singleDestinationDWARF(&b)
	path := writeDWARFELF(t, dwarfAbbreviations(), b.info())
	paths, ok := resolveH3PeerPaths(path, 0, "github.com/quic-go/quic-go/http3.SingleDestinationRoundTripper")
	if !ok || paths.Client.NSteps != 3 || paths.Client.Steps[0] != (h3PeerStep{Off: 16, Iface: 1}) {
		t.Fatalf("client path = %+v (%v), want 3 steps starting at the Connection interface", paths.Client, ok)
	}
}

func TestHTTP3SitesPublishThePeerPathsResolvedFromDWARF(t *testing.T) {
	var b dwarfBuilder
	quicServerDWARF(&b, false)
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	writeTestELF(t, filepath.Join(base, "4288", "exe"), append(rustLikeSections("main.main"),
		testSection{name: ".debug_abbrev", typ: shtProgbits, data: dwarfAbbreviations()},
		testSection{name: ".debug_info", typ: shtProgbits, data: b.info()}))
	f := installFakeAttacher(t, nil)
	maps := withLayoutMaps(t, "h3_offsets", "h3_peer_paths_map")
	origReturns := goFuncReturns
	t.Cleanup(func() { goFuncReturns = origReturns })
	goFuncReturns = func(_, sym string) (uint64, []uint64, bool) {
		if sym == "github.com/quic-go/quic-go/http3.requestFromHeaders" {
			return 0x300, []uint64{0x310}, true
		}
		return 0, nil, false
	}
	links := AttachGoHTTP3Probes(placeholderPrograms("uprobe_h3_req_from_headers_ret"), 4288)
	if len(links) != 1 || len(f.calls) != 1 {
		t.Fatalf("links=%d calls=%+v, want the one return site", len(links), f.calls)
	}
	paths, ok := maps["h3_peer_paths_map"].values[f.calls[0].cookie].(h3PeerPaths)
	if !ok || paths.Server.NSteps != 3 {
		t.Fatalf("h3_peer_paths_map = %v, want the 3-step server path under the site's cookie", maps["h3_peer_paths_map"].values)
	}
	_ = links[0].Close()
	if len(maps["h3_peer_paths_map"].values) != 0 {
		t.Fatal("the peer paths outlived their site")
	}
}
