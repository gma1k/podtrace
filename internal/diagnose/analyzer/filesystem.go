package analyzer

import (
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

type weighted struct {
	ms     float64
	weight uint64
}

// AnalyzeFSWithKernelCounts is AnalyzeFS over the events plus the kernel's
// counts. Percentiles weigh each kernel bucket by its count at the bucket's
// upper bound, so a fast operation is never read as faster than it was.
func AnalyzeFSWithKernelCounts(evs []*events.Event, kernel FSKernelCounts, fsSlowThreshold float64) FSStats {
	var s FSStats
	var samples []weighted
	var totalNS float64
	maxBytes := safeconv.Int64ToUint64(config.MaxBytesForBandwidth)

	for _, e := range evs {
		switch e.Type {
		case events.EventWrite:
			s.Writes++
		case events.EventRead:
			s.Reads++
		case events.EventFsync:
			s.Fsyncs++
		default:
			continue
		}
		ms := float64(e.LatencyNS) / float64(config.NSPerMS)
		samples = append(samples, weighted{ms, 1})
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

	for typ, c := range kernel {
		switch typ {
		case events.EventWrite:
			s.Writes += c.Count
		case events.EventRead:
			s.Reads += c.Count
		case events.EventFsync:
			s.Fsyncs += c.Count
		default:
			continue
		}
		s.KernelCounted += c.Count
		totalNS += float64(c.SumNS)
		s.TotalBytes += c.Bytes
		for upper, n := range c.Buckets {
			samples = append(samples, weighted{upper, n})
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
	s.P50 = weightedPercentile(samples, ops, 50)
	s.P95 = weightedPercentile(samples, ops, 95)
	s.P99 = weightedPercentile(samples, ops, 99)
	return s
}

// weightedPercentile returns the smallest value at or below which p percent
// of the weight lies.
func weightedPercentile(sorted []weighted, total uint64, p float64) float64 {
	target := p / 100 * float64(total)
	var seen float64
	for _, s := range sorted {
		seen += float64(s.weight)
		if seen >= target {
			return s.ms
		}
	}
	return sorted[len(sorted)-1].ms
}
