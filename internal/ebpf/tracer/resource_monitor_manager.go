package tracer

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/resource"
)

// resourceMonitorManager keeps one resource.ResourceMonitor per target cgroup
// and reconciles that set as the tracer's cgroup targets change.
type resourceMonitorManager struct {
	mu sync.Mutex

	desired map[string]struct{}

	running map[string]stoppable

	active bool

	startMonitor func(path string) (stoppable, error)
}

type stoppable interface {
	Stop()
}

func newResourceMonitorManager() *resourceMonitorManager {
	return &resourceMonitorManager{
		desired: map[string]struct{}{},
		running: map[string]stoppable{},
	}
}

// reconcile records paths as the desired target set and, when the manager is
// active, starts monitors for newly-added cgroups and stops those removed.
func (m *resourceMonitorManager) reconcile(paths []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p != "" {
			desired[p] = struct{}{}
		}
	}
	m.desired = desired

	if m.active {
		m.reconcileLocked()
	}
}

// activate wires the shared maps + event channel and starts monitors for the
// current desired set.
func (m *resourceMonitorManager) activate(ctx context.Context, eventChan chan<- *events.Event, limitsMap, alertsMap, quotaMap *ebpf.Map) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limitsMap == nil || alertsMap == nil {
		logger.Warn("Resource monitor maps not found in BPF collection; resource alerts disabled")
		return
	}
	if m.startMonitor == nil {
		m.startMonitor = func(path string) (stoppable, error) {
			rm, err := resource.NewResourceMonitor(path, limitsMap, alertsMap, eventChan, "")
			if err != nil {
				return nil, err
			}
			if quotaMap != nil {
				rm.EnableBPFCPUSampler(quotaMap, alertsMap)
			}
			rm.Start(ctx)
			return rm, nil
		}
	}
	m.active = true
	m.reconcileLocked()
}

// reconcileLocked starts/stops monitors to match m.desired. Caller holds m.mu.
func (m *resourceMonitorManager) reconcileLocked() {
	// Stop monitors whose cgroup is no longer a target.
	for path, mon := range m.running {
		if _, ok := m.desired[path]; ok {
			continue
		}
		mon.Stop()
		delete(m.running, path)
		logger.Debug("Resource monitor stopped", zap.String("cgroup_path", path))
	}

	for path := range m.desired {
		if _, ok := m.running[path]; ok {
			continue
		}
		mon, err := m.startMonitor(path)
		if err != nil {
			logger.Warn("Failed to create resource monitor", zap.Error(err), zap.String("cgroup_path", path))
			continue
		}
		m.running[path] = mon
		logger.Debug("Resource monitor started", zap.String("cgroup_path", path))
	}
}

// stopAll tears down every monitor. Called from tracer Stop.
func (m *resourceMonitorManager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for path, mon := range m.running {
		mon.Stop()
		delete(m.running, path)
	}
	m.active = false
}

// runningCount reports how many monitors are live (used by tests).
func (m *resourceMonitorManager) runningCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.running)
}
