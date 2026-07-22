package tracer

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

func TestResourceMonitorManager_ActivateAssignsFactoryAndActivates(t *testing.T) {
	m := newResourceMonitorManager()
	limits := &ebpf.Map{}
	alerts := &ebpf.Map{}

	m.activate(context.Background(), nil, limits, alerts, nil)

	if !m.active {
		t.Error("manager not active after activate with non-nil maps")
	}
	m.mu.Lock()
	factorySet := m.startMonitor != nil
	m.mu.Unlock()
	if !factorySet {
		t.Error("activate did not install a startMonitor factory")
	}
	if got := m.runningCount(); got != 0 {
		t.Fatalf("running monitors with empty desired set = %d, want 0", got)
	}
}

func TestResourceMonitorManager_ReconcileSkipsFailedMonitors(t *testing.T) {
	m := newResourceMonitorManager()
	m.mu.Lock()
	m.startMonitor = func(path string) (stoppable, error) {
		if path == "/cg/bad" {
			return nil, fmt.Errorf("cannot start monitor for %s", path)
		}
		return &fakeMonitor{}, nil
	}
	m.active = true
	m.mu.Unlock()

	m.reconcile([]string{"/cg/good", "/cg/bad"})

	if got := m.runningCount(); got != 1 {
		t.Fatalf("running monitors = %d, want 1 (failed monitor must be skipped)", got)
	}
}
