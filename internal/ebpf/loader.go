package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// loadPodtrace loads the eBPF program
func loadPodtrace() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec("bpf/podtrace.bpf.o")
	if err != nil {
		spec, err = ebpf.LoadCollectionSpec("../bpf/podtrace.bpf.o")
		if err != nil {
			return nil, fmt.Errorf("failed to load eBPF program: %w (make sure to run 'make build' first)", err)
		}
	}

	return spec, nil
}
