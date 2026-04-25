// Package safeconv provides bounds-checked integer conversions.
//
// Go's built-in numeric conversions wrap silently when the source value
// does not fit the target type. eBPF tracers process kernel-emitted
// uint64 timestamps, byte counts, and PIDs that are then frequently
// narrowed to int64 for time.Unix, OTLP attributes, or display. A
// straight `int64(uint64Val)` cast can produce a negative number when
// the high bit is set — catastrophic for time arithmetic, surprising
// in dashboards, and flagged by gosec G115 / CodeQL.
//
// The helpers below saturate at the target type's boundary instead of
// wrapping. They are pure, allocation-free, and intended to be the
// only narrowing conversions used in the codebase.
package safeconv

import "math"

// Uint64ToInt64 converts an unsigned 64-bit value to a signed 64-bit
// value, saturating at math.MaxInt64. Use whenever a kernel timestamp,
// byte count, or other uint64 must be interpreted as int64 (e.g. for
// time.Unix or OTLP attributes).
func Uint64ToInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// Uint64BitsToInt64 reinterprets the bit pattern of v as a signed
// int64 — i.e. values with the high bit set become negative.
//
// Use only when the producer (typically a BPF program) has packed an
// int64 into a uint64 wire field and the consumer needs the original
// signed value back. Examples: an Event.Bytes field that polymorphically
// carries either a byte count OR a sentinel-encoded file descriptor.
//
// This is NOT a numeric conversion; it is an intentional bit-pattern
// re-interpretation. Saturation would corrupt the sentinel encoding,
// which is why this function exists separately from Uint64ToInt64.
func Uint64BitsToInt64(v uint64) int64 {
	return int64(v) // #nosec G115 -- bit-preserving reinterpretation is the documented contract
}

// Uint64ToInt32 saturates at math.MaxInt32. Used for narrowing kernel
// counters into int32 fields.
func Uint64ToInt32(v uint64) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(v)
}

// Uint64ToUint32 saturates at math.MaxUint32. Used when narrowing a
// uint64 (typically a kernel-derived count) to the uint32 cilium/ebpf
// expects for map sizes and probe IDs.
func Uint64ToUint32(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// Int32ToUint32 maps a signed 32-bit integer to unsigned. Negative
// values are clamped to 0 — appropriate for percentages, byte counts,
// and other quantities where negative is non-physical.
func Int32ToUint32(v int32) uint32 {
	if v < 0 {
		return 0
	}
	return uint32(v)
}

// Int64ToUint64 maps a signed 64-bit integer to unsigned. Negative
// values are clamped to 0.
func Int64ToUint64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// Int64ToUint32 narrows int64 to uint32, clamping negatives to 0 and
// over-large values to math.MaxUint32. Useful when a JSON parser or
// runtime API returns int64 but the consumer expects a uint32 PID,
// resource ID, etc.
func Int64ToUint32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// IntToInt32 narrows a (potentially 64-bit) int to int32, saturating
// at the int32 boundaries. Negative-friendly; preserves sign.
func IntToInt32(v int) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v)
}

// IntToUint32 narrows int to uint32, clamping negatives to 0 and
// over-large values to math.MaxUint32. Mirrors config.ClampUint32 so
// we have a single canonical helper for downstream callers that do
// not depend on the config package.
func IntToUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}
