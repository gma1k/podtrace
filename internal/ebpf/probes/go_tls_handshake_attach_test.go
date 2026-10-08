package probes

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type addressTarget struct {
	refuse   map[uint64]bool
	attached []uint64
	closed   []string
}

func (a *addressTarget) Uprobe(_ string, _ *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	if a.refuse[opts.Address] {
		return nil, errors.New("refused")
	}
	a.attached = append(a.attached, opts.Address)
	return namedFakeLink{name: "probe", closed: &a.closed}, nil
}

func (a *addressTarget) Uretprobe(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error) {
	return nil, errors.New("a Go function must not get a uretprobe")
}

func handshakeColl() *ebpf.Collection {
	return &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"uprobe_go_tls_handshake": {}, "uprobe_go_tls_handshake_ret": {},
	}}
}

func withGoFuncReturns(t *testing.T, offsets map[string][]uint64) {
	t.Helper()
	orig := goFuncReturns
	t.Cleanup(func() { goFuncReturns = orig })
	goFuncReturns = func(_, sym string) (uint64, []uint64, bool) {
		o, ok := offsets[sym]
		if !ok {
			return 0, nil, false
		}
		return o[0], o[1:], true
	}
}

func TestBothGoHandshakeFunctionsAreProbedAtEntryAndEveryReturn(t *testing.T) {
	withGoFuncReturns(t, map[string][]uint64{
		"crypto/tls.(*Conn).clientHandshake": {100, 110, 120},
		"crypto/tls.(*Conn).serverHandshake": {200, 210},
	})
	target := &addressTarget{}
	links := attachGoHandshakeProbes(handshakeColl(), target, "/bin/app", 1)
	if len(links) != 5 {
		t.Errorf("%d links, want an entry and every RET of both functions", len(links))
	}
	if target.attached[2] != 100 {
		t.Errorf("attached %v; the returns go first so no entry waits for a return that is not there", target.attached)
	}
}

func TestAGoHandshakeFunctionWithNoReturnAttachedGetsNoEntry(t *testing.T) {
	withGoFuncReturns(t, map[string][]uint64{"crypto/tls.(*Conn).clientHandshake": {100, 110}})
	target := &addressTarget{refuse: map[uint64]bool{110: true}}
	if links := attachGoHandshakeProbes(handshakeColl(), target, "/bin/app", 1); len(links) != 0 {
		t.Errorf("%d links; an entry with no return would record starts nothing consumes", len(links))
	}
}

func TestAGoHandshakeEntryThatCannotAttachReleasesItsReturns(t *testing.T) {
	withGoFuncReturns(t, map[string][]uint64{"crypto/tls.(*Conn).serverHandshake": {200, 210, 220}})
	target := &addressTarget{refuse: map[uint64]bool{200: true}}
	if links := attachGoHandshakeProbes(handshakeColl(), target, "/bin/app", 1); len(links) != 0 {
		t.Errorf("%d links with the entry refused", len(links))
	}
	if len(target.closed) != 2 {
		t.Errorf("closed %d return probes, want both", len(target.closed))
	}
}

func TestABinaryWithoutCryptoTLSIsSkipped(t *testing.T) {
	withGoFuncReturns(t, map[string][]uint64{})
	if links := attachGoHandshakeProbes(handshakeColl(), &addressTarget{}, "/bin/app", 1); len(links) != 0 {
		t.Errorf("%d links for a binary without crypto/tls", len(links))
	}
}

func TestGoHandshakeProbesNeedTheirPrograms(t *testing.T) {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	if links := attachGoHandshakeProbes(coll, &addressTarget{}, "/bin/app", 1); links != nil {
		t.Errorf("%d links with no programs", len(links))
	}
}

func TestTheGoHandshakeProgramsAreInTheTLSGroup(t *testing.T) {
	for _, p := range []string{"uprobe_go_tls_handshake", "uprobe_go_tls_handshake_ret"} {
		if GroupForProbe(p) != GroupTLS {
			t.Errorf("%s is not in the tls group", p)
		}
	}
}
