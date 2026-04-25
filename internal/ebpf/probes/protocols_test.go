package probes

import (
	"testing"

	"github.com/cilium/ebpf"
)

// emptyColl returns a Collection whose Programs map is empty so all
// branches that look up by program name fall into the "missing prog"
// path. This is enough to exercise the early-return / no-prog-found
// branches of every Attach* helper without needing a kernel.
func emptyColl() *ebpf.Collection {
	return &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
}

// All Attach*Probes wrappers below assert "no panic, length zero" when
// no compatible library is present on the host. The functions are
// allowed to return nil OR an empty slice; both are valid expressions
// of "no probes attached" — what we exercise is the early-out branch
// in each wrapper.

func TestAttachRedisProbes_NoLibFound(t *testing.T) {
	if got := AttachRedisProbes(emptyColl(), ""); len(got) != 0 {
		for _, l := range got {
			_ = l.Close()
		}
		t.Errorf("expected no links, got %d", len(got))
	}
	if got := AttachRedisProbes(emptyColl(), "nonexistent"); len(got) != 0 {
		for _, l := range got {
			_ = l.Close()
		}
		t.Errorf("expected no links, got %d", len(got))
	}
}

func TestAttachRedisProbesWithPID_NoMatch(t *testing.T) {
	if got := AttachRedisProbesWithPID(emptyColl(), "", 0); len(got) != 0 {
		t.Errorf("expected no links, got %d", len(got))
	}
}

func TestAttachMemcachedProbes_NoLibFound(t *testing.T) {
	if got := AttachMemcachedProbes(emptyColl(), ""); len(got) != 0 {
		t.Errorf("expected no links, got %d", len(got))
	}
	if got := AttachMemcachedProbes(emptyColl(), "nonexistent"); len(got) != 0 {
		t.Errorf("expected no links, got %d", len(got))
	}
}

func TestAttachMemcachedProbesWithPID_NoMatch(t *testing.T) {
	if got := AttachMemcachedProbesWithPID(emptyColl(), "", 0); len(got) != 0 {
		t.Errorf("expected no links, got %d", len(got))
	}
}

func TestAttachKafkaProbes_NoLibFound(t *testing.T) {
	if got := AttachKafkaProbes(emptyColl(), ""); len(got) != 0 {
		t.Errorf("expected no links, got %d", len(got))
	}
}

func TestAttachKafkaProbesWithPID_NoMatch(t *testing.T) {
	if got := AttachKafkaProbesWithPID(emptyColl(), "", 0); len(got) != 0 {
		t.Errorf("expected no links, got %d", len(got))
	}
}

// TestAttachFastCGIProbes_NoProgramsIsNoop: when the Collection has no
// matching kprobe programs, every iteration hits the `prog == nil`
// continue branch.
func TestAttachFastCGIProbes_NoProgramsIsNoop(t *testing.T) {
	got := AttachFastCGIProbes(emptyColl())
	if len(got) != 0 {
		// May be > 0 only if the test machine somehow has named
		// kprobe progs in the Collection — the empty Collection used
		// here guarantees this never happens.
		t.Errorf("got %d links, want 0", len(got))
	}
}

// TestAttachGRPCProbes_NoProgramsIsNoop: same idea for the single
// gRPC kprobe.
func TestAttachGRPCProbes_NoProgramsIsNoop(t *testing.T) {
	got := AttachGRPCProbes(emptyColl())
	if len(got) != 0 {
		t.Errorf("got %d links, want 0", len(got))
	}
}

// TestAttachUprobeSymbols_EmptyPairs covers the no-pairs branch — the
// loop body never runs and the helper returns an empty slice.
func TestAttachUprobeSymbols_EmptyPairs(t *testing.T) {
	links := attachUprobeSymbols(nil, emptyColl(), "/no/such/lib", nil)
	if links != nil {
		t.Errorf("expected nil for empty pairs, got %v", links)
	}
}

// TestAttachUprobeSymbols_AllProgsMissing: pairs with names that the
// Collection does not have — both inner if-blocks short-circuit, so
// the helper returns nil without touching the Executable.
func TestAttachUprobeSymbols_AllProgsMissing(t *testing.T) {
	pairs := []struct{ uprobe, uretprobe, symbol string }{
		{"missing_u", "missing_ur", "sym"},
	}
	links := attachUprobeSymbols(nil, emptyColl(), "/no/such/lib", pairs)
	if links != nil {
		t.Errorf("expected nil when all progs missing, got %v", links)
	}
}
