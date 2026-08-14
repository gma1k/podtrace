package tracer

import (
	"fmt"
	"sync"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/filter"
)

func TestCgroupPathAccessors_RoundTripAndEdges(t *testing.T) {
	tr := &Tracer{}

	if got := tr.primaryCgroupPath(); got != "" {
		t.Errorf("primaryCgroupPath on fresh tracer = %q, want empty", got)
	}
	if got := tr.currentCgroupPaths(); got != nil {
		t.Errorf("currentCgroupPaths on fresh tracer = %v, want nil", got)
	}

	tr.setCgroupPaths([]string{"/sys/fs/cgroup/a", "/sys/fs/cgroup/b"})
	if got := tr.primaryCgroupPath(); got != "/sys/fs/cgroup/a" {
		t.Errorf("primaryCgroupPath = %q, want /sys/fs/cgroup/a", got)
	}
	if got := tr.currentCgroupPaths(); len(got) != 2 || got[1] != "/sys/fs/cgroup/b" {
		t.Errorf("currentCgroupPaths = %v, want [/sys/fs/cgroup/a /sys/fs/cgroup/b]", got)
	}

	tr.setCgroupPaths(nil)
	if got := tr.primaryCgroupPath(); got != "" {
		t.Errorf("primaryCgroupPath after clear = %q, want empty", got)
	}
	if got := tr.currentCgroupPaths(); got != nil {
		t.Errorf("currentCgroupPaths after clear = %v, want nil", got)
	}

	tr.setCgroupPaths([]string{})
	if got := tr.primaryCgroupPath(); got != "" {
		t.Errorf("primaryCgroupPath on empty slice = %q, want empty", got)
	}
}

func TestCgroupPaths_ConcurrentWriteVsLockFreeRead(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	const iters = 3000

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if i%8 == 0 {
				_ = tr.SetCgroups(nil)
				continue
			}
			_ = tr.AttachToCgroups([]string{fmt.Sprintf("/sys/fs/cgroup/pod-%d", i)})
		}
	}()

	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = tr.primaryCgroupPath()
				for _, p := range tr.currentCgroupPaths() {
					_ = p
				}
				_ = tr.pidsForContainer("deadbeefdeadbeef", nil)
			}
		}()
	}

	wg.Wait()
}
