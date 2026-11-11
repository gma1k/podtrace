package analyzer

import (
	"math"
	"sort"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// FSKernelCount is what the kernel counted of one operation type without
// emitting events: operations too fast to become one. Buckets maps a latency
// upper bound in milliseconds to how many operations fell at or under it.
type FSKernelCount struct {
	Count   uint64
	SumNS   uint64
	Bytes   uint64
	Buckets map[float64]uint64
}

// FSKernelCounts holds a kernel count per operation type.
type FSKernelCounts map[events.EventType]FSKernelCount

// Total is the number of operations the kernel counted.
func (k FSKernelCounts) Total() uint64 {
	var n uint64
	for _, c := range k {
		n += c.Count
	}
	return n
}

// FSStats summarizes filesystem operations from their events and the
// kernel's counts of those too fast to become events.
type FSStats struct {
	Writes, Reads, Fsyncs uint64
	KernelCounted         uint64
	AvgMs, MaxMs          float64
	P50, P95, P99         float64
	SlowOps               int
	TotalBytes, AvgBytes  uint64
	MaxIsKernelUpperBound bool
}

// Ops is the number of operations of every type.
func (s FSStats) Ops() uint64 { return s.Writes + s.Reads + s.Fsyncs }

// IsFSEvent reports whether t is a filesystem operation the File System
// section counts.
func IsFSEvent(t events.EventType) bool {
	switch t {
	case events.EventWrite, events.EventRead, events.EventFsync:
		return true
	default:
		return false
	}
}

// FSEventKey is one cgroup's filesystem events of one operation type.
type FSEventKey struct {
	CgroupID uint64
	Type     events.EventType
}

// FSEventTotal is what every filesystem event under one key added up to,
// including the ones a full event buffer did not keep.
type FSEventTotal struct {
	Count   uint64
	SlowOps uint64
	SumNS   uint64
	MaxNS   uint64
	Bytes   uint64
}

// FSEventTotals holds an FSEventTotal per key. A full event buffer keeps only
// a sample of filesystem events, while the kernel's fast-operation counts are
// complete, so the File System section needs every event's totals to weigh
// one against the other.
type FSEventTotals map[FSEventKey]FSEventTotal

// Add counts e, a filesystem event, under its key.
func (t FSEventTotals) Add(e *events.Event, fsSlowThreshold float64) {
	if e == nil || !IsFSEvent(e.Type) {
		return
	}
	k := FSEventKey{CgroupID: e.CgroupID, Type: e.Type}
	tot := t[k]
	tot.Count++
	tot.SumNS += e.LatencyNS
	tot.MaxNS = max(tot.MaxNS, e.LatencyNS)
	if float64(e.LatencyNS)/float64(config.NSPerMS) > fsSlowThreshold {
		tot.SlowOps++
	}
	if e.Bytes > 0 && e.Bytes < safeconv.Int64ToUint64(config.MaxBytesForBandwidth) {
		tot.Bytes += e.Bytes
	}
	t[k] = tot
}

// Kept counts the filesystem events of evs under each key.
func Kept(evs []*events.Event) map[FSEventKey]uint64 {
	kept := make(map[FSEventKey]uint64)
	for _, e := range evs {
		if e != nil && IsFSEvent(e.Type) {
			kept[FSEventKey{CgroupID: e.CgroupID, Type: e.Type}]++
		}
	}
	return kept
}

// Share scales t to the part of each key that subset holds of the events
// kept under it, for a report on one pod of several: a key's whole total
// when subset holds all of them, a proportional part when it holds some, and
// nothing for a key subset holds none of. A partial share takes its maximum
// from subset's own events, since the key's maximum may belong to another.
func (t FSEventTotals) Share(subset []*events.Event, keptOverall map[FSEventKey]uint64) FSEventTotals {
	mine := Kept(subset)
	maxima := make(map[FSEventKey]uint64)
	for _, e := range subset {
		if e != nil && IsFSEvent(e.Type) {
			k := FSEventKey{CgroupID: e.CgroupID, Type: e.Type}
			maxima[k] = max(maxima[k], e.LatencyNS)
		}
	}
	out := make(FSEventTotals, len(mine))
	for k, n := range mine {
		tot, ok := t[k]
		all := keptOverall[k]
		if !ok || all == 0 {
			continue
		}
		if n >= all {
			out[k] = tot
			continue
		}
		ratio := float64(n) / float64(all)
		scale := func(v uint64) uint64 { return uint64(math.Round(float64(v) * ratio)) }
		out[k] = FSEventTotal{
			Count:   max(scale(tot.Count), n),
			SlowOps: scale(tot.SlowOps),
			SumNS:   scale(tot.SumNS),
			MaxNS:   maxima[k],
			Bytes:   scale(tot.Bytes),
		}
	}
	return out
}

type weighted struct {
	ms     float64
	weight float64
}

// AnalyzeFSWithKernelCounts is AnalyzeFS over the events plus the kernel's
// counts. Percentiles weigh each kernel bucket by its count at the bucket's
// upper bound, so a fast operation is never read as faster than it was.
func AnalyzeFSWithKernelCounts(evs []*events.Event, kernel FSKernelCounts, fsSlowThreshold float64) FSStats {
	return AnalyzeFSSampled(evs, nil, kernel, fsSlowThreshold)
}

// AnalyzeFSSampled is AnalyzeFSWithKernelCounts for evs that may be a sample
// of the filesystem events totals counted.
func AnalyzeFSSampled(evs []*events.Event, totals FSEventTotals, kernel FSKernelCounts, fsSlowThreshold float64) FSStats {
	var s FSStats
	var samples []weighted
	var totalNS float64
	maxBytes := safeconv.Int64ToUint64(config.MaxBytesForBandwidth)

	kept := Kept(evs)
	fromTotals := func(k FSEventKey) (FSEventTotal, bool) {
		tot, ok := totals[k]
		return tot, ok && tot.Count >= kept[k]
	}
	addOps := func(t events.EventType, n uint64) {
		switch t {
		case events.EventWrite:
			s.Writes += n
		case events.EventRead:
			s.Reads += n
		case events.EventFsync:
			s.Fsyncs += n
		}
	}

	for _, e := range evs {
		if e == nil || !IsFSEvent(e.Type) {
			continue
		}
		k := FSEventKey{CgroupID: e.CgroupID, Type: e.Type}
		ms := float64(e.LatencyNS) / float64(config.NSPerMS)
		if tot, ok := fromTotals(k); ok {
			samples = append(samples, weighted{ms, float64(tot.Count) / float64(kept[k])})
			continue
		}
		samples = append(samples, weighted{ms, 1})
		addOps(e.Type, 1)
		totalNS += float64(e.LatencyNS)
		if ms > s.MaxMs {
			s.MaxMs = ms
		}
		if ms > fsSlowThreshold {
			s.SlowOps++
		}
		if e.Bytes > 0 && e.Bytes < maxBytes {
			s.TotalBytes += e.Bytes
		}
	}

	for k := range totals {
		tot, ok := fromTotals(k)
		if !ok || tot.Count == 0 {
			continue
		}
		addOps(k.Type, tot.Count)
		totalNS += float64(tot.SumNS)
		s.MaxMs = max(s.MaxMs, float64(tot.MaxNS)/float64(config.NSPerMS))
		s.SlowOps += safeconv.Uint64ToInt(tot.SlowOps)
		s.TotalBytes += tot.Bytes
		if kept[k] == 0 {
			samples = append(samples, weighted{float64(tot.SumNS) / float64(tot.Count) / float64(config.NSPerMS), float64(tot.Count)})
		}
	}

	for typ, c := range kernel {
		if !IsFSEvent(typ) {
			continue
		}
		addOps(typ, c.Count)
		s.KernelCounted += c.Count
		totalNS += float64(c.SumNS)
		s.TotalBytes += c.Bytes
		for upper, n := range c.Buckets {
			samples = append(samples, weighted{upper, float64(n)})
			if upper > s.MaxMs {
				s.MaxMs = upper
				s.MaxIsKernelUpperBound = true
			}
		}
	}

	ops := s.Ops()
	if ops == 0 {
		return s
	}
	s.AvgMs = totalNS / float64(ops) / float64(config.NSPerMS)
	s.AvgBytes = s.TotalBytes / ops
	sort.Slice(samples, func(i, j int) bool { return samples[i].ms < samples[j].ms })
	s.P50 = weightedPercentile(samples, 50)
	s.P95 = weightedPercentile(samples, 95)
	s.P99 = weightedPercentile(samples, 99)
	return s
}

// weightedPercentile returns the smallest value at or below which p percent
// of the weight lies.
func weightedPercentile(sorted []weighted, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	var total float64
	for _, s := range sorted {
		total += s.weight
	}
	target := p / 100 * total
	var seen float64
	i := 0
	for ; i < len(sorted)-1; i++ {
		seen += sorted[i].weight
		if seen >= target {
			break
		}
	}
	return sorted[i].ms
}
