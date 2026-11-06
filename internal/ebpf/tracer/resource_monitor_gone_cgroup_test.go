package tracer

import (
	"fmt"
	"io/fs"
	"testing"
)

func TestAMonitorForACgroupThatIsAlreadyGoneIsSkippedAndRetried(t *testing.T) {
	m := newResourceMonitorManager()
	gone := true
	m.mu.Lock()
	m.startMonitor = func(path string, _ CgroupOwner) (resourceMonitorHandle, error) {
		if gone {
			return nil, fmt.Errorf("failed to get cgroup inode: %w", fs.ErrNotExist)
		}
		return &fakeMonitor{}, nil
	}
	m.active = true
	m.mu.Unlock()

	m.reconcile([]string{"/cg/deleted-pod"})
	if got := m.runningCount(); got != 0 {
		t.Fatalf("running monitors = %d for a cgroup that no longer exists", got)
	}

	gone = false
	m.reconcile([]string{"/cg/deleted-pod"})
	if got := m.runningCount(); got != 1 {
		t.Fatalf("running monitors = %d; a cgroup that appears later must still be monitored", got)
	}
}
