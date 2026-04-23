package agent

import (
	"context"
	"sync"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// Router is the agent's multi-CR merge layer.
//
// It tracks one CRRule per active PodTrace CR and exposes:
//
//   - Snapshot(): union of cgroup IDs across all rules → fed to the
//     tracer's TargetRegistry so the eBPF core attaches once.
//   - FilterUnion(): union of event filters across all rules → tells
//     the tracer which event categories to enable kernel-side.
//   - an implementation of tracer.Exporter that routes each event from
//     the tracer to the subset of CR exporters whose (cgroup, filter)
//     tuple matches.
type Router struct {
	mu    sync.RWMutex
	rules []CRRule
	stats *perCRStats
}

// NewRouter constructs an empty Router. The stats argument is shared
// with the status writer so per-CR event counts survive Publish calls
// (rules are replaced, counters are not).
func NewRouter(stats *perCRStats) *Router {
	if stats == nil {
		stats = newPerCRStats()
	}
	return &Router{
		rules: nil,
		stats: stats,
	}
}

// Publish atomically replaces the rule set. Callers must supply a
// *complete* snapshot; Publish does not merge. Rules are deep-copied
// defensively so the caller is free to mutate its own copy afterward.
//
// Per-CR stats are preserved for CRs that still appear in the new
// snapshot and dropped for CRs that are removed — so a CR that blinks
// out and back does not accumulate stale counters.
func (r *Router) Publish(rules []CRRule) {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := make(map[CRKey]struct{}, len(rules))
	cp := make([]CRRule, len(rules))
	for i, rule := range rules {
		cp[i] = cloneCRRule(rule)
		seen[rule.Key] = struct{}{}
	}

	// Drop stats for any CR that disappeared from this publish.
	for existing := range r.stats.snapshot() {
		if _, ok := seen[existing]; !ok {
			r.stats.drop(existing)
		}
	}

	r.rules = cp
}

// Snapshot returns the union of cgroup IDs across all active rules —
// the set the tracer should currently be attached to. Order is not
// guaranteed; uniqueness is.
func (r *Router) Snapshot() []uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := map[uint64]struct{}{}
	for _, rule := range r.rules {
		for id := range rule.CgroupIDs {
			seen[id] = struct{}{}
		}
	}
	out := make([]uint64, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// FilterUnion returns the union of enabled event filters across all
// active rules. The tracer uses this to decide which kprobe categories
// to attach kernel-side — attaching a kprobe nobody consumes wastes
// per-event CPU.
func (r *Router) FilterUnion() []events.EventType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := map[events.EventType]struct{}{}
	for _, rule := range r.rules {
		for t := range rule.Filters {
			seen[t] = struct{}{}
		}
	}
	out := make([]events.EventType, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	return out
}

// RulesSnapshot returns a read-only copy of the current rules. Used by
// the status writer and by tests.
func (r *Router) RulesSnapshot() []CRRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CRRule, len(r.rules))
	copy(out, r.rules)
	return out
}

// Stats exposes the shared per-CR counter table.
func (r *Router) Stats() *perCRStats { return r.stats }

// Name implements tracer.Exporter.
func (r *Router) Name() string { return "cr-router" }

// Export implements tracer.Exporter. It dispatches each event in the
// batch to the subset of CR exporters whose cgroup set contains the
// event's CgroupID AND whose filters include the event's type.
//
// A single event may fan out to multiple exporters (overlapping CRs)
// or to none (an event from a cgroup no CR currently claims — rare,
// usually means the tracer saw a detach-in-progress). In either case
// we count the event against every CR that received it.
//
// Dispatch errors from one exporter must not abort delivery to others;
// the router records the error via incrDropped and continues. This
// matches pkg/tracer.Engine's contract that exporter failures are
// non-fatal.
func (r *Router) Export(ctx context.Context, batch []*events.Event) error {
	r.mu.RLock()
	rules := r.rules
	r.mu.RUnlock()

	if len(rules) == 0 || len(batch) == 0 {
		return nil
	}

	// Per-rule filtered batches: amortises allocations when many rules
	// overlap the same cgroup set.
	filtered := make([][]*events.Event, len(rules))
	for i := range rules {
		filtered[i] = filtered[i][:0]
	}

	for _, ev := range batch {
		if ev == nil {
			continue
		}
		for i := range rules {
			if !matchRule(&rules[i], ev) {
				continue
			}
			filtered[i] = append(filtered[i], ev)
		}
	}

	for i := range rules {
		if len(filtered[i]) == 0 {
			continue
		}
		if err := rules[i].Exporter.Export(ctx, filtered[i]); err != nil {
			r.stats.incrDropped(rules[i].Key, int64(len(filtered[i])))
			continue
		}
		r.stats.incr(rules[i].Key, int64(len(filtered[i])))
	}
	return nil
}

// Close implements tracer.Exporter. Called once during tracer shutdown.
// Closes every downstream exporter; collects errors but never fails fast.
func (r *Router) Close(ctx context.Context) error {
	r.mu.Lock()
	rules := r.rules
	r.rules = nil
	r.mu.Unlock()

	for _, rule := range rules {
		if rule.Exporter == nil {
			continue
		}
		_ = rule.Exporter.Close(ctx)
	}
	return nil
}

// matchRule returns true when event `ev` should be delivered to the
// exporter for `rule`. Both conditions must hold:
//
//  1. The event's cgroup ID is in the rule's cgroup set (the rule's
//     PodTrace claims that pod right now).
//  2. The event's type is enabled in the rule's filter set (the rule's
//     PodTrace opted into that event category).
//
// Rule (1) relies on the kernel's cgroup-ID delivery semantics: our
// kprobes stamp the task's cgroup inode on each event, so the agent
// can route without knowing the per-pod path.
func matchRule(rule *CRRule, ev *events.Event) bool {
	if _, ok := rule.CgroupIDs[ev.CgroupID]; !ok {
		return false
	}
	// Empty filter set means "no categories accepted" rather than "all
	// accepted" — the operator always seeds a non-empty default, but we
	// defend against an empty CR spec here to avoid a silent flood.
	if len(rule.Filters) == 0 {
		return false
	}
	_, ok := rule.Filters[ev.Type]
	return ok
}

// cloneCRRule returns a defensive copy of a CRRule. The maps are
// reallocated; the Exporter reference is shared (Exporters are
// intentionally long-lived — constructing one on every Publish would
// reopen connections).
func cloneCRRule(in CRRule) CRRule {
	out := CRRule{
		Key:            in.Key,
		Exporter:       in.Exporter,
		BundleRevision: in.BundleRevision,
		MatchedPods:    in.MatchedPods,
	}
	if in.CgroupIDs != nil {
		out.CgroupIDs = make(map[uint64]struct{}, len(in.CgroupIDs))
		for k := range in.CgroupIDs {
			out.CgroupIDs[k] = struct{}{}
		}
	}
	if in.Filters != nil {
		out.Filters = make(map[events.EventType]struct{}, len(in.Filters))
		for k := range in.Filters {
			out.Filters[k] = struct{}{}
		}
	}
	return out
}

// compile-time check that Router satisfies tracer.Exporter.
var _ tracer.Exporter = (*Router)(nil)