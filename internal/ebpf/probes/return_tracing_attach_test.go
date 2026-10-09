package probes

import (
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type namedLink struct {
	link.Link
	name string
}

func (l namedLink) Close() error { return nil }

func stubReturnCollection(names ...string) (*ebpf.Collection, map[*ebpf.Program]string) {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	byProg := map[*ebpf.Program]string{}
	for _, n := range names {
		p := &ebpf.Program{}
		coll.Programs[n] = p
		byProg[p] = n
	}
	return coll, byProg
}

func withTracingAttach(t *testing.T, fn func(*ebpf.Program) (link.Link, error)) {
	t.Helper()
	orig := attachTracing
	t.Cleanup(func() { attachTracing = orig })
	attachTracing = fn
}

func TestAReturnProbeIsAttachedAsFexitWhenItCanBe(t *testing.T) {
	coll, names := stubReturnCollection("kretprobe_tcp_recvmsg", "fexit_tcp_recvmsg")
	withTracingAttach(t, func(p *ebpf.Program) (link.Link, error) { return namedLink{name: names[p]}, nil })
	l, err := attachReturn(coll, "kretprobe_tcp_recvmsg", func() (link.Link, error) {
		return namedLink{name: "kretprobe"}, nil
	})
	if err != nil || l.(namedLink).name != "fexit_tcp_recvmsg" {
		t.Errorf("attached %v, %v; want the fexit", l, err)
	}
}

func TestAReturnProbeFallsBackToTheKretprobe(t *testing.T) {
	for name, c := range map[string]struct {
		programs []string
		fexitErr error
	}{
		"no fexit build in the collection": {programs: []string{"kretprobe_tcp_recvmsg"}},
		"the fexit does not attach":        {programs: []string{"kretprobe_tcp_recvmsg", "fexit_tcp_recvmsg"}, fexitErr: errors.New("no trampoline")},
		"a probe with no fexit build":      {programs: []string{"kretprobe_tcp_connect"}},
	} {
		t.Run(name, func(t *testing.T) {
			coll, names := stubReturnCollection(c.programs...)
			withTracingAttach(t, func(p *ebpf.Program) (link.Link, error) {
				if c.fexitErr != nil {
					return nil, c.fexitErr
				}
				return namedLink{name: names[p]}, nil
			})
			l, err := attachReturn(coll, c.programs[0], func() (link.Link, error) { return namedLink{name: "kretprobe"}, nil })
			if err != nil || l.(namedLink).name != "kretprobe" {
				t.Errorf("attached %v, %v; want the kretprobe", l, err)
			}
		})
	}
}

func TestAKretprobeFailureIsReported(t *testing.T) {
	coll, _ := stubReturnCollection("kretprobe_tcp_connect")
	want := errors.New("no such symbol")
	if _, err := attachReturn(coll, "kretprobe_tcp_connect", func() (link.Link, error) { return nil, want }); !errors.Is(err, want) {
		t.Errorf("err %v, want %v", err, want)
	}
}

func TestTheFexitBuildsAreListedOnceInOrder(t *testing.T) {
	got := ReturnTracingPrograms()
	if !sort.StringsAreSorted(got) || len(got) != len(returnTracing) {
		t.Errorf("got %v", got)
	}
	pairs := ReturnTracingPairs()
	pairs["kretprobe_tcp_recvmsg"] = "changed"
	if reflect.DeepEqual(pairs, returnTracing) {
		t.Error("ReturnTracingPairs hands out the table itself")
	}
}
