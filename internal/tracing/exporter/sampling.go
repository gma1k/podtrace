package exporter

import (
	"hash/fnv"
	"math"
)

// sampleTrace decides deterministically whether a trace is exported at the
// given rate, by hashing the trace ID onto [0, 1).
func sampleTrace(traceID string, rate float64) bool {
	if rate >= 1.0 {
		return true
	}
	if rate <= 0.0 {
		return false
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(traceID))
	return float64(h.Sum64())/float64(math.MaxUint64) < rate
}
