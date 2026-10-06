package probes

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// fsProbe is a filesystem operation traced by an entry and an exit program,
// built twice: as fentry/fexit, a trampoline that costs a fraction of a
// kprobe and has no instance pool to run out of, and as kprobe/kretprobe for
// kernels without it.
type fsProbe struct {
	symbol        string
	fentry, fexit string
	kprobe, kret  string
	mandatory     bool
}

var fsProbes = []fsProbe{
	{"vfs_read", "fentry_vfs_read", "fexit_vfs_read", "kprobe_vfs_read", "kretprobe_vfs_read", true},
	{"vfs_write", "fentry_vfs_write", "fexit_vfs_write", "kprobe_vfs_write", "kretprobe_vfs_write", true},
}

// FSTracingPrograms names the fentry/fexit builds, which a loader drops from
// the spec where the kernel cannot load them.
func FSTracingPrograms() []string {
	out := make([]string, 0, 2*len(fsProbes))
	for _, p := range fsProbes {
		out = append(out, p.fentry, p.fexit)
	}
	return out
}

// errFSProgramsAbsent is a collection built without an operation's
// programs, which is skipped like any absent program rather than failed.
var errFSProgramsAbsent = errors.New("the operation's programs are not in the collection")

const (
	mechanismFentry = "fentry"
	mechanismKprobe = "kprobe"
)

var (
	attachTracing = func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachTracing(link.TracingOptions{Program: prog})
	}
	attachKprobePair = attachKprobe
)

// attachFSProbe attaches one operation's pair, preferring fentry/fexit. The
// exit is attached before the entry, so no entry is ever recorded with
// nothing to consume it.
func attachFSProbe(coll *ebpf.Collection, p fsProbe) ([]link.Link, string, error) {
	var tracingErr error
	if fexit, fentry := coll.Programs[p.fexit], coll.Programs[p.fentry]; fexit != nil && fentry != nil {
		links, err := attachPair(
			func() (link.Link, error) { return attachTracing(fexit) },
			func() (link.Link, error) { return attachTracing(fentry) },
		)
		if err == nil {
			return links, mechanismFentry, nil
		}
		tracingErr = err
	}
	kret, kprobe := coll.Programs[p.kret], coll.Programs[p.kprobe]
	if kret == nil || kprobe == nil {
		if tracingErr != nil {
			return nil, "", tracingErr
		}
		return nil, "", errFSProgramsAbsent
	}
	links, err := attachPair(
		func() (link.Link, error) { return attachKprobePair(p.kret, p.symbol, kret) },
		func() (link.Link, error) { return attachKprobePair(p.kprobe, p.symbol, kprobe) },
	)
	if err != nil {
		return nil, "", errors.Join(tracingErr, err)
	}
	if tracingErr != nil {
		logger.Debug("fentry/fexit unavailable; the filesystem probe uses kprobes",
			zap.String("symbol", p.symbol), zap.Error(tracingErr))
	}
	return links, mechanismKprobe, nil
}

func attachPair(first, second func() (link.Link, error)) ([]link.Link, error) {
	a, err := first()
	if err != nil {
		return nil, err
	}
	b, err := second()
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	return []link.Link{a, b}, nil
}

// attachFSProbes attaches every filesystem operation. A mandatory operation
// that cannot attach either way is returned as failed, with every link
// already made closed; an optional one is skipped and named in skipped.
func attachFSProbes(coll *ebpf.Collection) (links []link.Link, skipped []string, failed *fsAttachError) {
	used := map[string][]string{}
	for _, p := range fsProbes {
		ls, mechanism, attachErr := attachFSProbe(coll, p)
		if errors.Is(attachErr, errFSProgramsAbsent) {
			logger.Debug("Filesystem probe programs not in the collection, skipping",
				zap.String("symbol", p.symbol))
			continue
		}
		if attachErr != nil {
			if p.mandatory {
				for _, l := range links {
					_ = l.Close()
				}
				return nil, nil, &fsAttachError{probe: p, err: attachErr}
			}
			skipped = append(skipped, p.symbol)
			continue
		}
		links = append(links, ls...)
		used[mechanism] = append(used[mechanism], p.symbol)
	}
	if len(used) > 0 {
		logger.Info("Filesystem probes attached",
			zap.Strings(mechanismFentry, used[mechanismFentry]),
			zap.Strings(mechanismKprobe, used[mechanismKprobe]))
	}
	return links, skipped, nil
}

type fsAttachError struct {
	probe fsProbe
	err   error
}

func (e *fsAttachError) Error() string {
	return fmt.Sprintf("filesystem probe %s could not attach as fentry/fexit or as a kprobe: %v", e.probe.symbol, e.err)
}

func (e *fsAttachError) Unwrap() error { return e.err }
