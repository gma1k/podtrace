// Package memlimit gives the Go runtime the memory limit of the container it
// runs in.
//
// Go does not read the cgroup memory limit, so on its own the garbage
// collector lets the heap grow to twice what was live after the last cycle
// and the kernel kills the process before Go has collected anything. Loading
// the eBPF object allocates about 380 MiB, most of it short-lived, which was
// enough to kill session Jobs under their 512 MiB limit.
package memlimit

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

const share = 0.7

const unlimitedV1 = 1 << 62

const (
	cgroupV2Limit = "memory.max"
	cgroupV1Limit = "memory/memory.limit_in_bytes"
)

var (
	cgroupRoot = "/sys/fs/cgroup"
	setLimit   = debug.SetMemoryLimit
	getenv     = os.Getenv
)

// Apply sets Go's soft memory limit to a share of the container's memory
// limit and returns it. It sets nothing, and returns 0, when GOMEMLIMIT is
// set, which the runtime has already applied, or when there is no limit.
func Apply() int64 {
	if getenv("GOMEMLIMIT") != "" {
		return 0
	}
	limit, ok := containerLimit()
	if !ok {
		return 0
	}
	soft := int64(float64(limit) * share)
	setLimit(soft)
	return soft
}

// containerLimit reads the memory limit of the cgroup the process runs in,
// which inside a container is the container's own.
func containerLimit() (int64, bool) {
	root, err := os.OpenRoot(cgroupRoot)
	if err != nil {
		return 0, false
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{cgroupV2Limit, cgroupV1Limit} {
		data, err := root.ReadFile(name)
		if err != nil {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil || n <= 0 || n >= unlimitedV1 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
