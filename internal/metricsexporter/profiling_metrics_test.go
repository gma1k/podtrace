package metricsexporter

import "testing"

// These three helpers are thin wrappers around prometheus
// Counter/Gauge.With(...).{Set,Inc}() — there is nothing semantic to
// assert beyond "does not panic and registers the labels".

func TestRecordProfilingGoroutines(t *testing.T) {
	RecordProfilingGoroutines("10.0.0.1", 50, 5)
	RecordProfilingGoroutines("", 0, 0) // empty pod IP
}

func TestRecordProfilingAutoTrigger(t *testing.T) {
	RecordProfilingAutoTrigger("10.0.0.1")
	RecordProfilingAutoTrigger("")
	RecordProfilingAutoTrigger("10.0.0.1") // increment again
}

func TestRecordProfilingFetchError(t *testing.T) {
	RecordProfilingFetchError("10.0.0.1", "heap")
	RecordProfilingFetchError("10.0.0.1", "goroutine")
	RecordProfilingFetchError("", "")
}
