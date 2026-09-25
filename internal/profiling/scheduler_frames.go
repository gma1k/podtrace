package profiling

import "strings"

// schedulerFrames are the Go runtime functions a goroutine or thread passes
// through on its way off the CPU, plus the roots every goroutine stack shares.
var schedulerFrames = map[string]struct{}{
	"runtime.schedule":            {},
	"runtime.park_m":              {},
	"runtime.findRunnable":        {},
	"runtime.findrunnable":        {},
	"runtime.stealWork":           {},
	"runtime.runqgrab":            {},
	"runtime.runqsteal":           {},
	"runtime.checkTimers":         {},
	"runtime.netpoll":             {},
	"runtime.pollWork":            {},
	"runtime.startm":              {},
	"runtime.wakep":               {},
	"runtime.handoffp":            {},
	"runtime.resetspinning":       {},
	"runtime.mcall":               {},
	"runtime.gopark":              {},
	"runtime.goparkunlock":        {},
	"runtime.gosched_m":           {},
	"runtime.goschedImpl":         {},
	"runtime.gopreempt_m":         {},
	"runtime.goexit":              {},
	"runtime.goexit0":             {},
	"runtime.goexit1":             {},
	"runtime.stopm":               {},
	"runtime.mPark":               {},
	"runtime.mstart":              {},
	"runtime.mstart0":             {},
	"runtime.mstart1":             {},
	"runtime.rt0_go":              {},
	"runtime.notesleep":           {},
	"runtime.notetsleep":          {},
	"runtime.notetsleep_internal": {},
	"runtime.notetsleepg":         {},
	"runtime.futexsleep":          {},
	"runtime.futex":               {},
	"runtime.semasleep":           {},
	"runtime.usleep":              {},
	"runtime.osyield":             {},
	"runtime.systemstack":         {},
	"runtime.systemstack_switch":  {},
	"runtime.morestack":           {},
	"runtime.newstack":            {},
	"runtime.sysmon":              {},
	"runtime.templateThread":      {},
}

// isSchedulerFrame reports whether a resolved frame is Go scheduler
// machinery. Assembly functions carry an ABI suffix in the symbol table
// (runtime.goexit.abi0), which is stripped before matching.
func isSchedulerFrame(name string) bool {
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".abi0"), ".abi1")
	_, ok := schedulerFrames[name]
	return ok
}
