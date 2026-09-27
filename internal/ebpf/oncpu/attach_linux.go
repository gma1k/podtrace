//go:build linux

package oncpu

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	perfEventOpen = unix.PerfEventOpen
	setBPF        = func(fd, progFD int) error { return unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, progFD) }
	closeFD       = unix.Close
)

// openCPUClock opens a cpu-clock perf event on one CPU that fires SampleHz
// times a second for whichever task is running there.
func openCPUClock(cpu int) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: SampleHz,
		Bits:   unix.PerfBitFreq,
	}
	return perfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
}
