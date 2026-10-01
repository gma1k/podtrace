package tracer

import "runtime/debug"

// loadGCPercent is the GOGC the tracer loads its eBPF object under. Parsing
// the object and its BTF and loading every program allocates about 380 MiB,
// most of it garbage within the same load, and at the default of 100 the heap
// grows to twice what is live before Go collects: a 512 MiB session Job was
// killed for its memory in the middle of loading. At 25 the heap stays close
// to what is live, at the cost of more collections for the second or so the
// load takes.
const loadGCPercent = 25

func tightGCForLoad() func() {
	prev := debug.SetGCPercent(loadGCPercent)
	return func() {
		debug.SetGCPercent(prev)
		debug.FreeOSMemory()
	}
}
