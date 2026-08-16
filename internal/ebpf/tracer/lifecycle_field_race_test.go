package tracer

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func TestSetDropReporter_ConcurrentWithReportDrop(t *testing.T) {
	tr := &Tracer{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100000; i++ {
			tr.SetDropReporter(func(string, int) {})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100000; i++ {
			tr.reportDrop("ringbuf_full", 1)
		}
	}()
	wg.Wait()
}

func TestSetContainerIDs_ConcurrentWrites(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
	tr.attachContainerGroupFn = func(probes.ProbeGroup, string, []uint32) []link.Link { return nil }

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			id := fmt.Sprintf("container%04d", g)
			for i := 0; i < 200; i++ {
				_ = tr.SetContainerIDs([]string{id})
			}
		}(g)
	}
	wg.Wait()

	if got := tr.lastContainerID(); got == "" {
		t.Fatal("expected a container ID to be recorded")
	}
}
