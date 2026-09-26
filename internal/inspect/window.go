package inspect

import (
	"sort"
	"time"
)

// A rule needs rates, and a rate needs two points.
type Window struct {
	Prev Snapshot
	Cur  Snapshot
}

// Interval is the elapsed time the rates are computed over.
func (w Window) Interval() time.Duration {
	if w.Prev.IsZero() || w.Cur.IsZero() {
		return 0
	}
	return w.Cur.At.Sub(w.Prev.At)
}

// Ready reports whether rates can be computed.
func (w Window) Ready() bool { return w.Interval() > 0 }

// Delta is one series' change across the window.
type Delta struct {
	Sample Sample

	Value float64

	Count uint64
	Sum   float64

	Buckets []Bucket

	Reset bool
}

// FractionAbove returns the share of this window's observations that exceeded
// bound, as a percentage, reporting false when the window cannot answer:
// nothing observed, a counter reset, no buckets, or no bucket boundary at
// bound.
func (d Delta) FractionAbove(bound float64) (float64, bool) {
	if d.Reset || d.Count == 0 || len(d.Buckets) == 0 {
		return 0, false
	}
	if d.Sample.NativeBuckets {
		return d.nativeFractionAbove(bound)
	}
	for _, b := range d.Buckets {
		if b.UpperBound != bound {
			continue
		}
		if b.Count > d.Count {
			return 0, false
		}
		return float64(d.Count-b.Count) / float64(d.Count) * 100, true
	}
	return 0, false
}

func (d Delta) nativeFractionAbove(bound float64) (float64, bool) {
	if bound <= 0 {
		return 0, false
	}
	edge := nativeBoundaryAtOrAbove(bound, d.Sample.NativeSchema)
	var atOrBelow uint64
	for _, b := range d.Buckets {
		if b.UpperBound > edge*(1+1e-9) {
			break
		}
		atOrBelow = b.Count
	}
	if atOrBelow > d.Count {
		return 0, false
	}
	return float64(d.Count-atOrBelow) / float64(d.Count) * 100, true
}

// Mean returns the mean observation over the window, reporting false when
// nothing was observed.
func (d Delta) Mean() (float64, bool) {
	if d.Reset || d.Count == 0 {
		return 0, false
	}
	return d.Sum / float64(d.Count), true
}

func (d Delta) PerSecond(interval time.Duration) float64 {
	if d.Reset || interval <= 0 {
		return 0
	}
	return d.Value / interval.Seconds()
}

// Deltas returns one Delta per series of a counter or histogram family.
func (w Window) Deltas(family string) []Delta {
	cur := w.Cur.Family(family)
	if len(cur) == 0 {
		return nil
	}

	previous := make(map[string]Sample, len(w.Prev.Family(family)))
	for _, s := range w.Prev.Family(family) {
		previous[seriesKey(s)] = s
	}

	out := make([]Delta, 0, len(cur))
	for _, s := range cur {
		d := Delta{Sample: s, Value: s.Value, Count: s.Count, Sum: s.Sum, Buckets: s.Buckets}
		if before, ok := previous[seriesKey(s)]; ok {
			if s.Value < before.Value || s.Count < before.Count {
				d.Reset = true
			} else {
				d.Value = s.Value - before.Value
				d.Count = s.Count - before.Count
				d.Sum = s.Sum - before.Sum
				d.Buckets = bucketDelta(before.Buckets, s.Buckets)
			}
		}
		out = append(out, d)
	}
	return out
}

// bucketDelta subtracts one gather's cumulative buckets from the next.
func bucketDelta(before, cur []Bucket) []Bucket {
	if len(cur) == 0 {
		return nil
	}
	out := make([]Bucket, 0, len(cur))
	j := 0
	var was uint64
	for _, b := range cur {
		for j < len(before) && before[j].UpperBound <= b.UpperBound {
			was = before[j].Count
			j++
		}
		if b.Count < was {
			return nil
		}
		out = append(out, Bucket{UpperBound: b.UpperBound, Count: b.Count - was})
	}
	return out
}

// Gauges returns the current value of every series of a gauge family. A gauge
// needs no window: its value is already the reading.
func (w Window) Gauges(family string) []Sample { return w.Cur.Family(family) }

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
