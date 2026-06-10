package tracer

import (
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/podtrace/podtrace/internal/ebpf/probes"
)

// fakeLink counts Close calls so the tests can assert single-close
// semantics.
type fakeLink struct {
	link.Link
	closes atomic.Int32
}

func (f *fakeLink) Close() error {
	f.closes.Add(1)
	return nil
}

// TestDisableProbeGroup_RemovesLinksFromFlatRegistry is a regression test:
// DisableProbeGroup closed a group's links but left them in t.links, so
// Stop() double-closed them and repeated disable/enable cycles grew t.links
// with dead handles indefinitely.
func TestDisableProbeGroup_RemovesLinksFromFlatRegistry(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}

	grouped := &fakeLink{}
	ungrouped := &fakeLink{}
	tr.registerGroupLinks(probes.GroupFastCGI, []link.Link{grouped})
	tr.addLinks([]link.Link{ungrouped})

	if tr.linkCount() != 2 {
		t.Fatalf("linkCount = %d, want 2", tr.linkCount())
	}

	if err := tr.DisableProbeGroup(probes.GroupFastCGI); err != nil {
		t.Fatalf("DisableProbeGroup: %v", err)
	}
	if grouped.closes.Load() != 1 {
		t.Errorf("grouped link closes = %d, want 1", grouped.closes.Load())
	}
	if tr.linkCount() != 1 {
		t.Errorf("linkCount after disable = %d, want 1 (closed links must leave the registry)", tr.linkCount())
	}

	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if grouped.closes.Load() != 1 {
		t.Errorf("grouped link closes after Stop = %d, want 1 (no double-close)", grouped.closes.Load())
	}
	if ungrouped.closes.Load() != 1 {
		t.Errorf("ungrouped link closes after Stop = %d, want 1", ungrouped.closes.Load())
	}
}

// TestRegisterGroupLinks_GroupGating: container-scoped uprobe batches must be
// registered under their probe group so SetEnabledCategories and the
// management endpoints can actually detach them — they used to land only in
// the flat registry, making the FastCGI/TLS gating a silent no-op.
func TestRegisterGroupLinks_GroupGating(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
	l := &fakeLink{}
	tr.registerGroupLinks(probes.GroupTLS, []link.Link{l})

	tr.probeGroupsMu.Lock()
	registered := len(tr.probeGroups[probes.GroupTLS])
	tr.probeGroupsMu.Unlock()
	if registered != 1 {
		t.Fatalf("GroupTLS registry has %d links, want 1", registered)
	}

	if err := tr.DisableProbeGroup(probes.GroupTLS); err != nil {
		t.Fatalf("DisableProbeGroup: %v", err)
	}
	if l.closes.Load() != 1 {
		t.Errorf("TLS uprobe link closes = %d, want 1 (gating must detach it)", l.closes.Load())
	}
}
