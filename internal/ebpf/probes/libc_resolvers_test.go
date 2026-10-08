package probes

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func hostLibc(t *testing.T) *executable {
	t.Helper()
	for _, p := range []string{"/lib/x86_64-linux-gnu/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		exe, err := openExecutable(p)
		if err != nil {
			t.Skipf("cannot open %s: %v", p, err)
		}
		return exe
	}
	t.Skip("no libc on this host")
	return nil
}

func TestEveryLibcResolverIsInTheDNSGroup(t *testing.T) {
	for _, fn := range libcResolvers {
		for _, prog := range []string{"uprobe_" + fn, "uretprobe_" + fn} {
			if GroupForProbe(prog) != GroupTLS {
				t.Errorf("%s is not in the group the libc DNS probes attach with", prog)
			}
		}
	}
}

func TestAResolverWithoutItsProgramsIsSkipped(t *testing.T) {
	exe := hostLibc(t)
	if links := attachLibcResolver(&ebpf.Collection{Programs: map[string]*ebpf.Program{}}, exe, "gethostbyname_r"); links != nil {
		t.Errorf("attached %d links with no programs", len(links))
	}
}

func TestAResolverThatCannotAttachLeavesNothingBehind(t *testing.T) {
	exe := hostLibc(t)
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"uprobe_gethostbyname_r": {}, "uretprobe_gethostbyname_r": {},
	}}
	if links := attachLibcResolver(coll, exe, "gethostbyname_r"); links != nil {
		t.Errorf("attached %d links from programs that were never loaded", len(links))
	}
}

type entryRefusingTarget struct {
	closed []string
}

func (f *entryRefusingTarget) Uretprobe(symbol string, _ *ebpf.Program, _ *link.UprobeOptions) (link.Link, error) {
	return namedFakeLink{name: "ret:" + symbol, closed: &f.closed}, nil
}

func (f *entryRefusingTarget) Uprobe(symbol string, _ *ebpf.Program, _ *link.UprobeOptions) (link.Link, error) {
	return nil, errors.New("refused: " + symbol)
}

func TestAResolverWhoseEntryCannotAttachReleasesItsReturnProbe(t *testing.T) {
	target := &entryRefusingTarget{}
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"uprobe_gethostbyname2_r": {}, "uretprobe_gethostbyname2_r": {},
	}}
	if links := attachLibcResolver(coll, target, "gethostbyname2_r"); links != nil {
		t.Errorf("attached %d links with the entry probe refused", len(links))
	}
	if len(target.closed) != 1 || target.closed[0] != "ret:gethostbyname2_r" {
		t.Errorf("closed %v; the return probe would wait for entries that never come", target.closed)
	}
}
