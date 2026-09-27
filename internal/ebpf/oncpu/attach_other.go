//go:build !linux

package oncpu

import "errors"

// errNotLinux reports that perf events, and so the sampler, exist only on
// Linux. The package still builds elsewhere so the CLI, which only reads what
// the agents sampled, can be cross-compiled.
var errNotLinux = errors.New("oncpu: the on-CPU sampler needs Linux perf events")

var (
	setBPF  = func(int, int) error { return errNotLinux }
	closeFD = func(int) error { return nil }
)

func openCPUClock(int) (int, error) { return -1, errNotLinux }
