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
	mu       sync.RWMutex
	rules    []CRRule
	stats    *perCRStats
	enricher *PodEnricher
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

// WithEnricher returns a Router that stamps each forwarded event with
// the matching K8sMetadata before delegating to the per-CR exporters.
func (r *Router) WithEnricher(e *PodEnricher) *Router {
	r.enricher = e
	return r
}

func (r *Router) Publish(rules []CRRule) {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := make(map[CRKey]struct{}, len(rules))
	cp := make([]CRRule, len(rules))
	for i, rule := range rules {
		cp[i] = cloneCRRule(rule)
		seen[rule.Key] = struct{}{}
	}

	for existing := range r.stats.snapshot() {
		if _, ok := seen[existing]; !ok {
			r.stats.drop(existing)
		}
	}

	r.rules = cp
}

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

func (r *Router) RulesSnapshot() []CRRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CRRule, len(r.rules))
	copy(out, r.rules)
	return out
}

func (r *Router) Stats() *perCRStats { return r.stats }

func (r *Router) Name() string { return "cr-router" }

func (r *Router) Export(ctx context.Context, batch []*events.Event) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rules := r.rules
	enricher := r.enricher

	if len(rules) == 0 || len(batch) == 0 {
		return nil
	}

	filtered := make([][]*events.Event, len(rules))
	for i := range rules {
		filtered[i] = filtered[i][:0]
	}

	// One lookup per event regardless of how many CRs (and exporters)
	// claim it.
	enrichBatch(enricher, batch)

	for _, ev := range batch {
		if ev == nil {
			continue
		}
		for i := range rules {
			if rules[i].Err != nil || rules[i].Exporter == nil {
				continue
			}
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
		if rules[i].Exporter == nil {
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

// matchRule decides whether an event is forwarded to a given CR's
// exporter.
func matchRule(rule *CRRule, ev *events.Event) bool {
	if _, ok := rule.CgroupIDs[ev.CgroupID]; !ok {
		return false
	}
	if len(rule.Filters) == 0 {
		return true
	}
	_, ok := rule.Filters[ev.Type]
	return ok
}

func cloneCRRule(in CRRule) CRRule {
	out := CRRule{
		Key:            in.Key,
		Exporter:       in.Exporter,
		BundleRevision: in.BundleRevision,
		MatchedPods:    in.MatchedPods,
		Err:            in.Err,
		Policy:         clonePolicySnapshot(in.Policy),
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

// clonePolicySnapshot deep-copies a PolicySnapshot so router consumers
// can safely retain a reference past a Publish call.
func clonePolicySnapshot(in PolicySnapshot) PolicySnapshot {
	out := PolicySnapshot{
		Hash:       in.Hash,
		Generation: in.Generation,
	}
	if in.EffectiveSamplePercent != nil {
		v := *in.EffectiveSamplePercent
		out.EffectiveSamplePercent = &v
	}
	if in.Filters != nil {
		out.Filters = append([]string(nil), in.Filters...)
	}
	if in.Thresholds != nil {
		t := *in.Thresholds
		out.Thresholds = &t
		if t.ErrorRatePercent != nil {
			v := *t.ErrorRatePercent
			out.Thresholds.ErrorRatePercent = &v
		}
		if t.RTTSpikeMs != nil {
			v := *t.RTTSpikeMs
			out.Thresholds.RTTSpikeMs = &v
		}
		if t.FSSlowMs != nil {
			v := *t.FSSlowMs
			out.Thresholds.FSSlowMs = &v
		}
	}
	return out
}

// compile-time check that Router satisfies tracer.Exporter.
var _ tracer.Exporter = (*Router)(nil)
