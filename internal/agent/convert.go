package agent

import "github.com/podtrace/podtrace/internal/safeconv"

// safeUint64ToInt64 saturates a uint64 at math.MaxInt64. Thin
// re-export of safeconv.Uint64ToInt64 kept only so existing call sites
// inside the agent package don't need a package-qualified rename in
// every spot. New code should call safeconv directly.
func safeUint64ToInt64(v uint64) int64 { return safeconv.Uint64ToInt64(v) }

// lenToInt32 narrows a len() result to int32 — negative values are
// clamped to 0, oversize values to math.MaxInt32. Same shape as
// safeconv.IntToInt32 except the len() callers never produce negative
// inputs in practice; we keep the explicit non-negative clamp for
// defense in depth.
func lenToInt32(v int) int32 {
	if v < 0 {
		return 0
	}
	return safeconv.IntToInt32(v)
}
