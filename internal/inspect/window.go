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

	Reset bool
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
		d := Delta{Sample: s, Value: s.Value, Count: s.Count, Sum: s.Sum}
		if before, ok := previous[seriesKey(s)]; ok {
			if s.Value < before.Value || s.Count < before.Count {
				d.Reset = true
			} else {
				d.Value = s.Value - before.Value
				d.Count = s.Count - before.Count
				d.Sum = s.Sum - before.Sum
			}
		}
		out = append(out, d)
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
