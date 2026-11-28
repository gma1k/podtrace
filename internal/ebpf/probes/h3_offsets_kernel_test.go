//go:build bpf_loadtest && linux

package probes

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/safeconv"
)

func hashMap(t *testing.T, value any) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  uint32(binary.Size(value)),
		MaxEntries: 8,
	})
	if err != nil {
		t.Skipf("cannot create a map (needs privileges): %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func realReturnSites(t *testing.T, bin, sym string) {
	t.Helper()
	entry, rets, ok := goFuncReturnOffsets(bin, sym)
	if !ok {
		t.Skipf("%s has no return sites in %s", sym, bin)
	}
	orig := goFuncReturns
	t.Cleanup(func() { goFuncReturns = orig })
	goFuncReturns = func(_, s string) (uint64, []uint64, bool) {
		if s == "github.com/quic-go/quic-go/http3.(*ClientConn).RoundTrip" || s == "database/sql.(*DB).conn" {
			return entry, rets, true
		}
		return 0, nil, false
	}
}

func cookieOf(t *testing.T, path string) uint64 {
	t.Helper()
	exe, err := openExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	return layoutCookie(exe)
}

func TestKernelAnHTTP3LayoutIsPublishedUnderItsSiteCookieWhileTheSitesAreAttached(t *testing.T) {
	prog := uprobeProgram(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	realReturnSites(t, self, "testing.tRunner")
	offsets := hashMap(t, h3FieldOffsets{})
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{"uprobe_h3_roundtrip": prog, "uprobe_h3_roundtrip_ret": prog},
		Maps: map[string]*ebpf.Map{
			"h3_offsets":        offsets,
			"h3_peer_paths_map": hashMap(t, h3PeerPaths{}),
		},
	}
	links := AttachGoHTTP3Probes(coll, safeconv.IntToUint32(os.Getpid()))
	if len(links) < 2 {
		t.Fatalf("attached %d links, want the roundtrip entry and its returns", len(links))
	}
	cookie := cookieOf(t, self)
	var got h3FieldOffsets
	if err := offsets.Lookup(&cookie, &got); err != nil || got != h3DefaultOffsets {
		t.Fatalf("h3_offsets[%x] = %+v, %v; want the default offsets while the sites are attached", cookie, got, err)
	}
	for _, l := range links {
		_ = l.Close()
	}
	if err := offsets.Lookup(&cookie, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("h3_offsets[%x] = %+v, %v after every site closed; want it deleted", cookie, got, err)
	}
}
