package agent

import (
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/safeconv"
)

// Tunables for the per-CR rolling error-rate detector.
const (
	errorRateWindowSeconds = 60
	errorRateMinSampleSize = 20
)

// errorRateDetector evaluates a per-CR error-rate threshold over a
// rolling N-second window of buckets.
type errorRateDetector struct {
	mu      sync.Mutex
	buckets [errorRateWindowSeconds]errorRateBucket

	threshold int32

	breached bool
	nowFn    func() time.Time
}

// errorRateBucket holds the (total, errors) counts for one wall-clock
// second.
type errorRateBucket struct {
	second uint64
	total  int64
	errors int64
}

func newErrorRateDetector(thresholdPercent int32) *errorRateDetector {
	return &errorRateDetector{
		threshold: thresholdPercent,
		nowFn:     time.Now,
	}
}

// setThreshold updates the configured threshold percentage without
// disturbing the window state.
func (d *errorRateDetector) setThreshold(thresholdPercent int32) {
	d.mu.Lock()
	d.threshold = thresholdPercent
	d.mu.Unlock()
}

// Observe records one event and returns true iff this event caused a
// "below-threshold to above-threshold" transition.
func (d *errorRateDetector) Observe(isError bool) (justBreached bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.nowFn()
	sec := safeconv.Int64ToUint64(now.Unix())
	idx := int(sec % errorRateWindowSeconds)

	b := &d.buckets[idx]
	if b.second != sec {
		b.second = sec
		b.total = 0
		b.errors = 0
	}
	b.total++
	if isError {
		b.errors++
	}

	var cutoff uint64
	if sec+1 > errorRateWindowSeconds {
		cutoff = sec + 1 - errorRateWindowSeconds
	}
	var total, errors int64
	for i := range d.buckets {
		bb := &d.buckets[i]
		if bb.second >= cutoff && bb.second <= sec {
			total += bb.total
			errors += bb.errors
		}
	}

	if total < errorRateMinSampleSize {
		if d.breached {
			d.breached = false
		}
		return false
	}

	above := errors*100 > total*int64(d.threshold)
	if above && !d.breached {
		d.breached = true
		return true
	}
	if !above && d.breached {
		d.breached = false
	}
	return false
}

// IsBreached returns the detector's current breach state without
// modifying it.
func (d *errorRateDetector) IsBreached() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.breached
}