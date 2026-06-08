package resource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type fakeBPFMap struct {
	mu      sync.Mutex
	entries map[uint64]interface{}
}

func newFakeBPFMap() *fakeBPFMap {
	return &fakeBPFMap{entries: make(map[uint64]interface{})}
}

func (f *fakeBPFMap) Put(key, value interface{}) error {
	k, ok := key.(uint64)
	if !ok {
		return fmt.Errorf("fakeBPFMap.Put: key must be uint64, got %T", key)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[k] = value
	return nil
}

func (f *fakeBPFMap) Delete(key interface{}) error {
	k, ok := key.(uint64)
	if !ok {
		return fmt.Errorf("fakeBPFMap.Delete: key must be uint64, got %T", key)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.entries[k]; !exists {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeBPFMap) get(key uint64) (interface{}, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.entries[key]
	return v, ok
}

// recordingSender captures alerts handed to the global alerting manager.
type recordingSender struct {
	ch chan *alerting.Alert
}

func (r *recordingSender) Send(_ context.Context, alert *alerting.Alert) error {
	select {
	case r.ch <- alert:
	default:
	}
	return nil
}

func (r *recordingSender) Name() string { return "recording" }

func waitForResourceAlert(t *testing.T, ch chan *alerting.Alert) bool {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case a := <-ch:
			if a.Source != "resource_monitor" {
				continue
			}
			if a.Namespace != "test-ns" {
				t.Errorf("alert namespace = %q, want test-ns", a.Namespace)
			}
			return true
		case <-deadline:
			return false
		}
	}
}

// useEnabledAlertManager installs a global alerting manager that is enabled
// and routes alerts to a recording sender, restoring prior state afterwards.
// Returns the channel alerts land on.
func useEnabledAlertManager(t *testing.T) chan *alerting.Alert {
	t.Helper()

	origEnabled := config.AlertingEnabled
	origWebhook := config.AlertWebhookURL
	config.AlertingEnabled = true
	config.AlertWebhookURL = "http://127.0.0.1:0/unused"

	mgr, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if !mgr.IsEnabled() {
		t.Fatalf("expected enabled alerting manager")
	}

	rec := &recordingSender{ch: make(chan *alerting.Alert, 16)}
	mgr.AddSender(rec)

	origMgr := alerting.GetGlobalManager()
	alerting.SetGlobalManager(mgr)

	t.Cleanup(func() {
		alerting.SetGlobalManager(origMgr)
		_ = mgr.Shutdown(context.Background())
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhook
	})

	return rec.ch
}

// newMonitorWithFakeMaps builds a ResourceMonitor whose limits/alerts maps are
// the supplied in-memory fakes, using a temp cgroup dir so the inode lookup in
// NewResourceMonitor succeeds. Pass nil to leave a map unset (nil-guard path).
func newMonitorWithFakeMaps(t *testing.T, limitsMap, alertsMap *fakeBPFMap, eventChan chan *events.Event) *ResourceMonitor {
	t.Helper()
	tmpDir := t.TempDir()
	useCgroupBase(t, tmpDir)
	cgroupPath := filepath.Join(tmpDir, "cg")
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir cgroup: %v", err)
	}
	rm, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}
	// Inject the fakes directly (same package). The interface fields stay nil
	// when a fake isn't supplied, preserving the nil-guard behaviour.
	if limitsMap != nil {
		rm.limitsMap = limitsMap
	}
	if alertsMap != nil {
		rm.alertsMap = alertsMap
	}
	return rm
}

func TestSyncToBPF_WritesLimitsToMap(t *testing.T) {
	limitsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, limitsMap, nil, nil)

	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceCPU: {
			LimitBytes:   100000,
			UsageBytes:   50000,
			LastUpdateNS: 12345,
			ResourceType: ResourceCPU,
		},
		ResourceMemory: {
			LimitBytes:   1 << 30,
			UsageBytes:   1 << 20,
			LastUpdateNS: 67890,
			ResourceType: ResourceMemory,
		},
	}
	rm.mu.Unlock()

	if err := rm.syncToBPF(); err != nil {
		t.Fatalf("syncToBPF() error = %v", err)
	}

	// All resource types share the cgroup-inode key, so the map holds one
	// entry: whichever type was written last. Assert it matches that type.
	raw, ok := limitsMap.get(rm.cgroupInode)
	if !ok {
		t.Fatalf("expected an entry at cgroup inode %d", rm.cgroupInode)
	}
	got, ok := raw.(limitMapValue)
	if !ok {
		t.Fatalf("map value has unexpected type %T", raw)
	}
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	expected := rm.limits[got.ResourceType]
	if expected == nil {
		t.Fatalf("map holds unknown resource type %d", got.ResourceType)
	}
	if got.LimitBytes != expected.LimitBytes ||
		got.UsageBytes != expected.UsageBytes ||
		got.LastUpdateNS != expected.LastUpdateNS {
		t.Errorf("map value mismatch: got %+v, expected limit %d usage %d updated %d",
			got, expected.LimitBytes, expected.UsageBytes, expected.LastUpdateNS)
	}
}

func TestSyncToBPF_EmptyLimits(t *testing.T) {
	limitsMap := newFakeBPFMap()
	rm := newMonitorWithFakeMaps(t, limitsMap, nil, nil)

	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{}
	rm.mu.Unlock()

	if err := rm.syncToBPF(); err != nil {
		t.Fatalf("syncToBPF() error = %v", err)
	}
	if _, ok := limitsMap.get(rm.cgroupInode); ok {
		t.Errorf("expected no entry in map")
	}
}

func TestSyncToBPF_NilMapIsNoOp(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, nil)
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceCPU: {LimitBytes: 100, UsageBytes: 50, ResourceType: ResourceCPU},
	}
	rm.mu.Unlock()
	if err := rm.syncToBPF(); err != nil {
		t.Fatalf("syncToBPF() with nil map should be a no-op, got %v", err)
	}
}

func TestCheckAlerts_AlertLevels(t *testing.T) {
	tests := []struct {
		name          string
		usage         uint64
		limit         uint64
		wantLevel     uint32
		wantEntry     bool
		wantEvent     bool
		wantManagerOn bool
	}{
		{name: "no breach", usage: 10, limit: 100, wantLevel: AlertNone, wantEntry: false, wantEvent: false, wantManagerOn: false},
		{name: "warning", usage: 85, limit: 100, wantLevel: AlertWarning, wantEntry: true, wantEvent: true, wantManagerOn: true},
		{name: "critical", usage: 92, limit: 100, wantLevel: AlertCritical, wantEntry: true, wantEvent: true, wantManagerOn: true},
		{name: "emergency", usage: 99, limit: 100, wantLevel: AlertEmergency, wantEntry: true, wantEvent: true, wantManagerOn: true},
		{name: "over 100 clamps to emergency", usage: 250, limit: 100, wantLevel: AlertEmergency, wantEntry: true, wantEvent: true, wantManagerOn: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alertCh := useEnabledAlertManager(t)
			alertsMap := newFakeBPFMap()
			eventChan := make(chan *events.Event, 4)
			rm := newMonitorWithFakeMaps(t, nil, alertsMap, eventChan)

			// Seed a prior warning so the "no breach" case exercises the
			// delete-existing branch.
			if err := alertsMap.Put(rm.cgroupInode, uint32(AlertWarning)); err != nil {
				t.Fatalf("seed alertsMap: %v", err)
			}

			rm.mu.Lock()
			rm.limits = map[uint32]*ResourceLimit{
				ResourceMemory: {
					LimitBytes:   tt.limit,
					UsageBytes:   tt.usage,
					ResourceType: ResourceMemory,
				},
			}
			rm.mu.Unlock()

			rm.checkAlerts()

			raw, ok := alertsMap.get(rm.cgroupInode)
			if !tt.wantEntry {
				if ok {
					t.Errorf("expected alertsMap entry deleted, but found %v", raw)
				}
			} else {
				if !ok {
					t.Fatalf("expected alertsMap entry")
				}
				if level := raw.(uint32); level != tt.wantLevel {
					t.Errorf("alertsMap level = %d, want %d", level, tt.wantLevel)
				}
			}

			select {
			case ev := <-eventChan:
				if !tt.wantEvent {
					t.Errorf("unexpected event emitted: %+v", ev)
				} else {
					if ev.Type != events.EventResourceLimit {
						t.Errorf("event type = %v, want EventResourceLimit", ev.Type)
					}
					if ev.LatencyNS != tt.limit {
						t.Errorf("event LatencyNS(limit) = %d, want %d", ev.LatencyNS, tt.limit)
					}
					if ev.Bytes != tt.usage {
						t.Errorf("event Bytes(usage) = %d, want %d", ev.Bytes, tt.usage)
					}
				}
			case <-time.After(200 * time.Millisecond):
				if tt.wantEvent {
					t.Error("expected an event but none was emitted")
				}
			}

			if tt.wantManagerOn {
				if !waitForResourceAlert(t, alertCh) {
					t.Error("expected alerting manager to receive a resource_monitor alert")
				}
			}
		})
	}
}

func TestCheckAlerts_BenignDeleteWhenAbsent(t *testing.T) {
	alertsMap := newFakeBPFMap()
	eventChan := make(chan *events.Event, 4)
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, eventChan)

	// Below the warning threshold and no prior entry: checkAlerts attempts a
	// Delete that returns ErrKeyNotExist, which must be treated as benign.
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 10, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	rm.checkAlerts()

	if _, ok := alertsMap.get(rm.cgroupInode); ok {
		t.Errorf("expected no alertsMap entry")
	}
}

func TestCheckAlerts_NilMapIsNoOp(t *testing.T) {
	rm := newMonitorWithFakeMaps(t, nil, nil, make(chan *events.Event, 1))
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 96, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()
	// Must not panic on a nil alertsMap.
	rm.checkAlerts()
}

func TestCheckAlerts_ZeroAndUnlimitedSkipped(t *testing.T) {
	alertsMap := newFakeBPFMap()
	eventChan := make(chan *events.Event, 4)
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, eventChan)

	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceCPU:    {LimitBytes: 0, UsageBytes: 5, ResourceType: ResourceCPU},
		ResourceMemory: {LimitBytes: ^uint64(0), UsageBytes: 5, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	rm.checkAlerts()

	if _, ok := alertsMap.get(rm.cgroupInode); ok {
		t.Errorf("expected no alertsMap entry")
	}
	select {
	case ev := <-eventChan:
		t.Errorf("expected no event, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCheckAlerts_UnknownResourceTypeLabel(t *testing.T) {
	useEnabledAlertManager(t)
	alertsMap := newFakeBPFMap()
	eventChan := make(chan *events.Event, 4)
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, eventChan)

	const unknownType uint32 = 99
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		unknownType: {LimitBytes: 100, UsageBytes: 96, ResourceType: unknownType},
	}
	rm.mu.Unlock()

	rm.checkAlerts()

	raw, ok := alertsMap.get(rm.cgroupInode)
	if !ok {
		t.Fatalf("expected alertsMap entry")
	}
	if level := raw.(uint32); level != AlertEmergency {
		t.Errorf("level = %d, want %d (emergency)", level, AlertEmergency)
	}
	select {
	case ev := <-eventChan:
		if ev.TCPState != unknownType {
			t.Errorf("event TCPState(resourceType) = %d, want %d", ev.TCPState, unknownType)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("expected an event for unknown resource type")
	}
}

func TestCheckAlerts_ChannelFullDoesNotBlock(t *testing.T) {
	useEnabledAlertManager(t)
	alertsMap := newFakeBPFMap()
	eventChan := make(chan *events.Event, 1)
	eventChan <- &events.Event{}
	rm := newMonitorWithFakeMaps(t, nil, alertsMap, eventChan)

	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 96, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	done := make(chan struct{})
	go func() {
		rm.checkAlerts()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("checkAlerts blocked on a full event channel")
	}

	// The map write still happened despite the dropped event.
	raw, ok := alertsMap.get(rm.cgroupInode)
	if !ok {
		t.Fatalf("expected alertsMap entry")
	}
	if level := raw.(uint32); level != AlertEmergency {
		t.Errorf("level = %d, want %d", level, AlertEmergency)
	}
}
