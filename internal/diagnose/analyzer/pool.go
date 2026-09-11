package analyzer

import (
	"sort"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

type PoolStats struct {
	TotalAcquires   int
	TotalReleases   int
	ExhaustedCount  int
	AvgWaitTime     time.Duration
	MaxWaitTime     time.Duration
	ReleaseRatio    float64
	PeakConnections int
	AvgConnections  float64
	P50WaitTime     float64
	P95WaitTime     float64
	P99WaitTime     float64
}

func AnalyzePool(acquireEvents, releaseEvents, exhaustedEvents []*events.Event) PoolStats {
	stats := PoolStats{
		TotalAcquires:  len(acquireEvents),
		TotalReleases:  len(releaseEvents),
		ExhaustedCount: len(exhaustedEvents),
	}

	if stats.TotalAcquires > 0 {
		stats.ReleaseRatio = float64(stats.TotalReleases) / float64(stats.TotalAcquires)
	}

	var waitTimes []float64
	var totalWaitTime time.Duration
	maxWaitTime := time.Duration(0)

	for _, e := range exhaustedEvents {
		waitTime := e.Latency()
		waitTimes = append(waitTimes, float64(waitTime.Nanoseconds())/float64(config.NSPerMS))
		totalWaitTime += waitTime
		if waitTime > maxWaitTime {
			maxWaitTime = waitTime
		}
	}

	if stats.ExhaustedCount > 0 {
		stats.AvgWaitTime = totalWaitTime / time.Duration(stats.ExhaustedCount)
		stats.MaxWaitTime = maxWaitTime

		if len(waitTimes) > 0 {
			sort.Float64s(waitTimes)
			stats.P50WaitTime = Percentile(waitTimes, 50)
			stats.P95WaitTime = Percentile(waitTimes, 95)
			stats.P99WaitTime = Percentile(waitTimes, 99)
		}
	}

	poolTracker := make(map[string]struct {
		current int
		peak    int
	})

	type poolEvent struct {
		ts     uint64
		target string
		acq    bool
	}
	timeline := make([]poolEvent, 0, len(acquireEvents)+len(releaseEvents))
	for _, e := range acquireEvents {
		timeline = append(timeline, poolEvent{ts: e.Timestamp, target: e.Target, acq: true})
	}
	for _, e := range releaseEvents {
		timeline = append(timeline, poolEvent{ts: e.Timestamp, target: e.Target, acq: false})
	}
	sort.SliceStable(timeline, func(i, j int) bool { return timeline[i].ts < timeline[j].ts })

	for _, ev := range timeline {
		poolID := ev.target
		if poolID == "" {
			poolID = "default"
		}
		pool := poolTracker[poolID]
		if ev.acq {
			pool.current++
			if pool.current > pool.peak {
				pool.peak = pool.current
			}
		} else if pool.current > 0 {
			pool.current--
		}
		poolTracker[poolID] = pool
	}

	totalPeak := 0
	totalCurrent := 0
	for _, pool := range poolTracker {
		if pool.peak > totalPeak {
			totalPeak = pool.peak
		}
		totalCurrent += pool.current
	}

	stats.PeakConnections = totalPeak
	if len(poolTracker) > 0 {
		stats.AvgConnections = float64(totalCurrent) / float64(len(poolTracker))
	}

	return stats
}

// AcquireWaitStats summarises time callers spent obtaining a pooled database
// connection, measured end to end across database/sql.(*DB).conn.
type AcquireWaitStats struct {
	Count int
	Total time.Duration
	Avg   time.Duration
	Max   time.Duration
	P50   float64
	P95   float64
	P99   float64
}

// AnalyzeAcquireWaits summarises connection-acquisition waits.
func AnalyzeAcquireWaits(acquireWaitEvents []*events.Event) AcquireWaitStats {
	stats := AcquireWaitStats{Count: len(acquireWaitEvents)}
	if stats.Count == 0 {
		return stats
	}

	waits := make([]float64, 0, len(acquireWaitEvents))
	for _, e := range acquireWaitEvents {
		d := e.Latency()
		stats.Total += d
		if d > stats.Max {
			stats.Max = d
		}
		waits = append(waits, float64(d.Nanoseconds())/float64(config.NSPerMS))
	}

	stats.Avg = stats.Total / time.Duration(stats.Count)
	sort.Float64s(waits)
	stats.P50 = Percentile(waits, 50)
	stats.P95 = Percentile(waits, 95)
	stats.P99 = Percentile(waits, 99)
	return stats
}
