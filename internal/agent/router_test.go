package agent

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// recExp is a per-test exporter that records each event it receives.
// Exposes an errTo-return knob so we can exercise the router's
// dropped-events counting path.
type recExp struct {
	mu      sync.Mutex
	name    string
	events  []*events.Event
	failOn  bool
	closed  int
	closeCh chan struct{}
}

func (e *recExp) Name() string { return e.name }
func (e *recExp) Export(_ context.Context, batch []*events.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failOn {
		return errors.New("export failed")
	}
	e.events = append(e.events, batch...)
	return nil
}
func (e *recExp) Close(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed++
	if e.closeCh != nil {
		close(e.closeCh)
	}
	return nil
}
func (e *recExp) count() int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.events) }

func mkRule(ns, name string, cgroupIDs []uint64, filters []events.EventType, exp tracer.Exporter) CRRule {
	cg := make(map[uint64]struct{}, len(cgroupIDs))
	for _, id := range cgroupIDs {
		cg[id] = struct{}{}
	}
	f := make(map[events.EventType]struct{}, len(filters))
	for _, t := range filters {
		f[t] = struct{}{}
	}
	return CRRule{
		Key:       CRKey{Namespace: ns, Name: name},
		CgroupIDs: cg,
		Filters:   f,
		Exporter:  exp,
	}
}

func TestRouter_SnapshotAndFilterUnion(t *testing.T) {
	r := NewRouter(nil)
	r.Publish([]CRRule{
		mkRule("a", "one", []uint64{1, 2}, []events.EventType{events.EventDNS}, &recExp{name: "a"}),
		mkRule("b", "two", []uint64{2, 3}, []events.EventType{events.EventConnect}, &recExp{name: "b"}),
	})
	if got := sortedUints(r.Snapshot()); !equalUints(got, []uint64{1, 2, 3}) {
		t.Errorf("Snapshot union wrong: %v", got)
	}
	if ft := r.FilterUnion(); len(ft) != 2 {
		t.Errorf("FilterUnion expected 2 filters, got %v", ft)
	}
}

// TestRouter_DispatchesByCgroupAndFilter is the core routing
// guarantee: overlapping CRs must produce correctly-scoped per-CR
// event streams.
func TestRouter_DispatchesByCgroupAndFilter(t *testing.T) {
	expA := &recExp{name: "a"}
	expB := &recExp{name: "b"}
	r := NewRouter(nil)
	// CR A: cgroup 100 + 200, filter DNS
	// CR B: cgroup 200 + 300, filter DNS + Connect
	r.Publish([]CRRule{
		mkRule("ns", "A", []uint64{100, 200}, []events.EventType{events.EventDNS}, expA),
		mkRule("ns", "B", []uint64{200, 300}, []events.EventType{events.EventDNS, events.EventConnect}, expB),
	})

	batch := []*events.Event{
		{CgroupID: 100, Type: events.EventDNS},      // A only
		{CgroupID: 200, Type: events.EventDNS},      // both
		{CgroupID: 200, Type: events.EventConnect},  // B only (A filtered it out)
		{CgroupID: 300, Type: events.EventDNS},      // B only
		{CgroupID: 999, Type: events.EventDNS},      // neither (cgroup not claimed)
	}
	if err := r.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if expA.count() != 2 {
		t.Errorf("A received %d, want 2 (cgroups 100 + 200 with DNS)", expA.count())
	}
	if expB.count() != 3 {
		t.Errorf("B received %d, want 3 (cgroups 200 DNS + 200 Connect + 300 DNS)", expB.count())
	}

	stats := r.Stats().snapshot()
	if stats[CRKey{"ns", "A"}].Events != 2 || stats[CRKey{"ns", "B"}].Events != 3 {
		t.Errorf("stats wrong: %+v", stats)
	}
}

func TestRouter_ExporterErrorIsCountedAsDrop(t *testing.T) {
	failing := &recExp{name: "fail", failOn: true}
	good := &recExp{name: "good"}
	r := NewRouter(nil)
	r.Publish([]CRRule{
		mkRule("ns", "bad", []uint64{1}, []events.EventType{events.EventDNS}, failing),
		mkRule("ns", "ok", []uint64{1}, []events.EventType{events.EventDNS}, good),
	})
	batch := []*events.Event{{CgroupID: 1, Type: events.EventDNS}}
	_ = r.Export(context.Background(), batch)

	stats := r.Stats().snapshot()
	if stats[CRKey{"ns", "bad"}].Dropped != 1 {
		t.Errorf("failing exporter should increment Dropped, got %+v", stats[CRKey{"ns", "bad"}])
	}
	if stats[CRKey{"ns", "ok"}].Events != 1 {
		t.Errorf("healthy exporter should still receive event, got %+v", stats[CRKey{"ns", "ok"}])
	}
	if good.count() != 1 {
		t.Errorf("good exporter count=%d, want 1", good.count())
	}
}

func TestRouter_EmptyFiltersDeliversNothing(t *testing.T) {
	exp := &recExp{name: "x"}
	r := NewRouter(nil)
	r.Publish([]CRRule{
		{Key: CRKey{"ns", "n"}, CgroupIDs: map[uint64]struct{}{1: {}}, Filters: nil, Exporter: exp},
	})
	_ = r.Export(context.Background(), []*events.Event{{CgroupID: 1, Type: events.EventDNS}})
	if exp.count() != 0 {
		t.Errorf("empty filter set should deliver zero events, got %d", exp.count())
	}
}

func TestRouter_CloseClosesEveryExporter(t *testing.T) {
	a := &recExp{name: "a"}
	b := &recExp{name: "b"}
	r := NewRouter(nil)
	r.Publish([]CRRule{
		mkRule("ns", "a", []uint64{1}, []events.EventType{events.EventDNS}, a),
		mkRule("ns", "b", []uint64{2}, []events.EventType{events.EventDNS}, b),
	})
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.closed != 1 || b.closed != 1 {
		t.Errorf("closed counts: a=%d b=%d (want 1,1)", a.closed, b.closed)
	}
}

// TestRouter_PublishDropsStaleStats makes sure a CR that disappears
// does not leave its counters behind forever — otherwise /metrics
// cardinality would grow unboundedly.
func TestRouter_PublishDropsStaleStats(t *testing.T) {
	r := NewRouter(nil)
	r.Publish([]CRRule{
		mkRule("ns", "stays", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{}),
		mkRule("ns", "goes", []uint64{2}, []events.EventType{events.EventDNS}, &recExp{}),
	})
	// Seed stats so "goes" has a non-zero counter that must get dropped.
	r.Stats().incr(CRKey{"ns", "goes"}, 5)

	r.Publish([]CRRule{
		mkRule("ns", "stays", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{}),
	})

	stats := r.Stats().snapshot()
	if _, ok := stats[CRKey{"ns", "goes"}]; ok {
		t.Errorf("stats for removed CR still present: %+v", stats)
	}
}

// TestRouter_Export_SkipsTombstoneRules covers the router's tombstone
// contract: a CRRule with Err != nil (or Exporter == nil) must be
// dropped during dispatch — never NPE, never deliver events to a nil
// exporter, never count the tombstone as a successful or dropped
// delivery. Healthy rules sharing the same cgroup must still receive
// their events.
func TestRouter_Export_SkipsTombstoneRules(t *testing.T) {
	good := &recExp{name: "good"}
	r := NewRouter(nil)
	r.Publish([]CRRule{
		{
			Key:       CRKey{"ns", "tomb"},
			CgroupIDs: map[uint64]struct{}{1: {}},
			Filters:   map[events.EventType]struct{}{events.EventDNS: {}},
			Exporter:  nil,
			Err:       errors.New("build exporter: not yet implemented"),
		},
		mkRule("ns", "ok", []uint64{1}, []events.EventType{events.EventDNS}, good),
	})

	batch := []*events.Event{{CgroupID: 1, Type: events.EventDNS}}
	if err := r.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if good.count() != 1 {
		t.Errorf("healthy exporter count = %d, want 1", good.count())
	}
	stats := r.Stats().snapshot()
	if stats[CRKey{"ns", "tomb"}].Events != 0 || stats[CRKey{"ns", "tomb"}].Dropped != 0 {
		t.Errorf("tombstone must not bump any counter, got %+v", stats[CRKey{"ns", "tomb"}])
	}
	if stats[CRKey{"ns", "ok"}].Events != 1 {
		t.Errorf("healthy CR events = %d, want 1", stats[CRKey{"ns", "ok"}].Events)
	}
}

// TestRouter_Export_TombstoneWithNilExporterButNoErr defends against
// a hypothetical caller that builds a CRRule with Exporter==nil but
// forgot to set Err. The dispatch path must still skip it rather than
// NPE — Exporter==nil is the canonical "do not dispatch" signal.
func TestRouter_Export_TombstoneWithNilExporterButNoErr(t *testing.T) {
	r := NewRouter(nil)
	r.Publish([]CRRule{
		{
			Key:       CRKey{"ns", "nilexp"},
			CgroupIDs: map[uint64]struct{}{1: {}},
			Filters:   map[events.EventType]struct{}{events.EventDNS: {}},
			Exporter:  nil,
		},
	})
	if err := r.Export(context.Background(), []*events.Event{{CgroupID: 1, Type: events.EventDNS}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
}

// TestRouter_Close_TombstonesAreSafeToClose asserts that Close handles
// tombstone rules (Exporter == nil) without panicking. Documents that
// the router's shutdown path coexists with the reconciler's tombstone
// pattern.
func TestRouter_Close_TombstonesAreSafeToClose(t *testing.T) {
	r := NewRouter(nil)
	r.Publish([]CRRule{
		{Key: CRKey{"ns", "tomb"}, Err: errors.New("x")},
		mkRule("ns", "ok", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{name: "ok"}),
	})
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestRouter_ConcurrentExportAndPublish(t *testing.T) {
	r := NewRouter(nil)
	exp := &recExp{name: "e"}
	r.Publish([]CRRule{mkRule("ns", "n", []uint64{1}, []events.EventType{events.EventDNS}, exp)})

	var wg sync.WaitGroup
	// Publisher: replace rules 50 times.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			r.Publish([]CRRule{mkRule("ns", "n", []uint64{uint64(i % 3)}, []events.EventType{events.EventDNS}, exp)})
		}
	}()
	// Exporter: push 500 events.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = r.Export(context.Background(), []*events.Event{{CgroupID: uint64(i % 3), Type: events.EventDNS}})
		}
	}()
	wg.Wait()
}

// helpers

func sortedUints(in []uint64) []uint64 {
	out := make([]uint64, len(in))
	copy(out, in)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
func equalUints(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
