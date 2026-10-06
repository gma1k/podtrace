package probes

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type namedFakeLink struct {
	link.Link
	name   string
	closed *[]string
}

func (f namedFakeLink) Close() error {
	*f.closed = append(*f.closed, f.name)
	return nil
}

type attachLog struct {
	attached []string
	closed   []string
	failing  map[string]bool
}

func (a *attachLog) attach(name string) (link.Link, error) {
	if a.failing[name] {
		return nil, errors.New("refused: " + name)
	}
	a.attached = append(a.attached, name)
	return namedFakeLink{name: name, closed: &a.closed}, nil
}

func withFakeAttach(t *testing.T, log *attachLog, coll *ebpf.Collection) {
	t.Helper()
	origTracing, origKprobe := attachTracing, attachKprobePair
	t.Cleanup(func() { attachTracing, attachKprobePair = origTracing, origKprobe })
	names := map[*ebpf.Program]string{}
	for name, p := range coll.Programs {
		names[p] = name
	}
	attachTracing = func(prog *ebpf.Program) (link.Link, error) { return log.attach(names[prog]) }
	attachKprobePair = func(progName, _ string, _ *ebpf.Program) (link.Link, error) { return log.attach(progName) }
}

func fsCollection(withFentry bool) *ebpf.Collection {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	for _, p := range fsProbes {
		coll.Programs[p.kprobe] = &ebpf.Program{}
		coll.Programs[p.kret] = &ebpf.Program{}
		if withFentry {
			coll.Programs[p.fentry] = &ebpf.Program{}
			coll.Programs[p.fexit] = &ebpf.Program{}
		}
	}
	return coll
}

func TestFilesystemProbesPreferFentryAndAttachTheExitFirst(t *testing.T) {
	coll := fsCollection(true)
	log := &attachLog{}
	withFakeAttach(t, log, coll)

	links, skipped, err := attachFSProbes(coll)
	if err != nil || len(skipped) != 0 || len(links) != 2*len(fsProbes) {
		t.Fatalf("links %d skipped %v err %v", len(links), skipped, err)
	}
	want := []string{"fexit_vfs_read", "fentry_vfs_read", "fexit_vfs_write", "fentry_vfs_write"}
	if !slices.Equal(log.attached, want) {
		t.Errorf("attached %v, want %v: the exit goes first so no entry waits for an exit that is not there", log.attached, want)
	}
}

func TestFilesystemProbesFallBackToKprobesWhenFentryCannotAttach(t *testing.T) {
	coll := fsCollection(true)
	log := &attachLog{failing: map[string]bool{"fentry_vfs_read": true}}
	withFakeAttach(t, log, coll)

	links, mechanism, err := attachFSProbe(coll, fsProbes[0])
	if err != nil || mechanism != mechanismKprobe || len(links) != 2 {
		t.Fatalf("links %d mechanism %q err %v", len(links), mechanism, err)
	}
	if !slices.Equal(log.closed, []string{"fexit_vfs_read"}) {
		t.Errorf("closed %v; the fexit attached before fentry failed must not be left behind", log.closed)
	}
	if !slices.Equal(log.attached[1:], []string{"kretprobe_vfs_read", "kprobe_vfs_read"}) {
		t.Errorf("attached %v", log.attached)
	}
}

func TestFilesystemProbesUseKprobesWhenTheFentryBuildWasPruned(t *testing.T) {
	coll := fsCollection(false)
	log := &attachLog{}
	withFakeAttach(t, log, coll)
	if _, mechanism, err := attachFSProbe(coll, fsProbes[1]); err != nil || mechanism != mechanismKprobe {
		t.Errorf("mechanism %q err %v", mechanism, err)
	}
}

func TestAMandatoryFilesystemProbeThatCannotAttachIsAnError(t *testing.T) {
	coll := fsCollection(true)
	log := &attachLog{failing: map[string]bool{"fexit_vfs_write": true, "kretprobe_vfs_write": true}}
	withFakeAttach(t, log, coll)

	links, _, err := attachFSProbes(coll)
	var fe *fsAttachError
	if !errors.As(err, &fe) || fe.probe.symbol != "vfs_write" || links != nil {
		t.Fatalf("links %v err %v", links, err)
	}
	if !slices.Contains(log.closed, "fentry_vfs_read") || !slices.Contains(log.closed, "fexit_vfs_read") {
		t.Errorf("closed %v; the probes already attached must be released", log.closed)
	}
	if fe.Error() == "" || errors.Unwrap(fe) == nil {
		t.Error("the error does not say what failed")
	}
}

func TestAnOptionalFilesystemProbeThatCannotAttachIsSkipped(t *testing.T) {
	orig := fsProbes
	t.Cleanup(func() { fsProbes = orig })
	fsProbes = append(append([]fsProbe(nil), orig...), fsProbe{"vfs_optional", "fentry_x", "fexit_x", "kprobe_x", "kretprobe_x", false})
	coll := fsCollection(true)
	log := &attachLog{failing: map[string]bool{"fexit_x": true, "kretprobe_x": true}}
	withFakeAttach(t, log, coll)

	_, skipped, err := attachFSProbes(coll)
	if err != nil || !slices.Equal(skipped, []string{"vfs_optional"}) {
		t.Errorf("skipped %v err %v", skipped, err)
	}
}

func TestEveryFilesystemTracingProgramIsNamed(t *testing.T) {
	names := FSTracingPrograms()
	if len(names) != 2*len(fsProbes) {
		t.Fatalf("names = %v", names)
	}
	for _, n := range names {
		if GroupForProbe(n) != GroupFileSystem {
			t.Errorf("%s is not in the filesystem probe group, so disabling the group leaves it attached", n)
		}
	}
}

func TestCloseTriesFileCloseFdBeforeCloseFd(t *testing.T) {
	orig := kprobeAttach
	t.Cleanup(func() { kprobeAttach = orig })
	var tried []string
	kprobeAttach = func(symbol string, _ *ebpf.Program, _ bool) (link.Link, error) {
		tried = append(tried, symbol)
		if symbol == "file_close_fd" {
			return nil, errors.New("not on this kernel")
		}
		return namedFakeLink{closed: new([]string)}, nil
	}
	if _, err := attachKprobe("kprobe_close_fd", "close_fd", &ebpf.Program{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tried, []string{"file_close_fd", "close_fd"}) {
		t.Errorf("tried %v; close(2) runs file_close_fd since Linux 6.7", tried)
	}
	tried = nil
	if _, err := attachKprobe("kretprobe_tcp_sendmsg", "tcp_sendmsg", &ebpf.Program{}); err != nil || !slices.Equal(tried, []string{"tcp_sendmsg"}) {
		t.Errorf("a probe with no alternative tried %v, %v", tried, err)
	}
}

func TestACollectionWithoutTheFilesystemProgramsIsSkippedNotFailed(t *testing.T) {
	links, skipped, err := attachFSProbes(&ebpf.Collection{Programs: map[string]*ebpf.Program{}})
	if err != nil || len(links) != 0 || len(skipped) != 0 {
		t.Errorf("links %v skipped %v err %v", links, skipped, err)
	}
}

func TestAFailedFentryWithNoKprobeBuildReportsTheFentryError(t *testing.T) {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{"fentry_vfs_read": {}, "fexit_vfs_read": {}}}
	log := &attachLog{failing: map[string]bool{"fexit_vfs_read": true}}
	withFakeAttach(t, log, coll)
	if _, _, err := attachFSProbe(coll, fsProbes[0]); err == nil || errors.Is(err, errFSProgramsAbsent) {
		t.Errorf("err = %v, want the fentry attach error", err)
	}
}

func TestStartupAttachPutsTheFilesystemProbesInTheirGroup(t *testing.T) {
	coll := fsCollection(true)
	withFakeAttach(t, &attachLog{}, coll)
	groups, err := AttachProbesByGroup(coll)
	if err != nil || len(groups[GroupFileSystem]) != 2*len(fsProbes) {
		t.Errorf("filesystem links %d err %v", len(groups[GroupFileSystem]), err)
	}
}

func TestStartupAttachFailsWhenAMandatoryFilesystemProbeCannotAttach(t *testing.T) {
	coll := fsCollection(true)
	withFakeAttach(t, &attachLog{failing: map[string]bool{"fexit_vfs_read": true, "kretprobe_vfs_read": true}}, coll)
	if _, err := AttachProbesByGroup(coll); err == nil || !strings.Contains(err.Error(), "vfs_read") {
		t.Errorf("err = %v, want one naming vfs_read", err)
	}
}

func TestStartupAttachListsASkippedOptionalFilesystemProbe(t *testing.T) {
	orig := fsProbes
	t.Cleanup(func() { fsProbes = orig })
	fsProbes = append(append([]fsProbe(nil), orig...), fsProbe{"vfs_optional", "fentry_x", "fexit_x", "kprobe_x", "kretprobe_x", false})
	coll := fsCollection(true)
	withFakeAttach(t, &attachLog{failing: map[string]bool{"fexit_x": true, "kretprobe_x": true}}, coll)
	if _, err := AttachProbesByGroup(coll); err != nil {
		t.Errorf("an optional probe failed the attach: %v", err)
	}
}

func TestReattachingTheFilesystemGroupAttachesItsProbes(t *testing.T) {
	coll := fsCollection(true)
	log := &attachLog{}
	withFakeAttach(t, log, coll)
	links, err := AttachProbeGroup(coll, GroupFileSystem)
	if err != nil || len(links) != 2*len(fsProbes) {
		t.Errorf("links %d err %v", len(links), err)
	}

	log.failing = map[string]bool{"fexit_vfs_write": true, "kretprobe_vfs_write": true}
	if _, err := AttachProbeGroup(coll, GroupFileSystem); err == nil {
		t.Error("a re-attach that could not attach vfs_write reported success")
	}
}

func TestTheDefaultKprobeAttachRefusesAProgramItCannotAttach(t *testing.T) {
	for _, ret := range []bool{false, true} {
		if _, err := kprobeAttach("vfs_read", &ebpf.Program{}, ret); err == nil {
			t.Errorf("ret=%v: attaching a program that was never loaded succeeded", ret)
		}
	}
	if _, err := attachTracing(&ebpf.Program{}); err == nil {
		t.Error("attaching an unloaded tracing program succeeded")
	}
}

func TestAnAlternativeSymbolThatAttachesIsUsed(t *testing.T) {
	orig := kprobeAttach
	t.Cleanup(func() { kprobeAttach = orig })
	var tried []string
	kprobeAttach = func(symbol string, _ *ebpf.Program, _ bool) (link.Link, error) {
		tried = append(tried, symbol)
		return namedFakeLink{closed: new([]string)}, nil
	}
	if _, err := attachKprobe("kprobe_close_fd", "close_fd", &ebpf.Program{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tried, []string{"file_close_fd"}) {
		t.Errorf("tried %v; on a kernel with file_close_fd, close_fd is not attached as well", tried)
	}
}
