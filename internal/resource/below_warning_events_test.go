package resource

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/events"
)

func TestARecoveredResourceIsReportedBelowTheWarningThreshold(t *testing.T) {
	eventChan := make(chan *events.Event, 4)
	rm := newMonitorWithFakeMaps(t, nil, newFakeBPFMap(), eventChan)
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 30, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()

	rm.checkAlerts()

	select {
	case ev := <-eventChan:
		if ev.Type != events.EventResourceLimit || ev.Error != 30 || ev.TCPState != ResourceMemory {
			t.Fatalf("event = %+v, want memory at 30%%", ev)
		}
	default:
		t.Fatal("no event below the warning threshold; the saturation gauge would keep the last breach")
	}
}

func TestAFullEventChannelBelowTheThresholdIsNotAnError(t *testing.T) {
	eventChan := make(chan *events.Event)
	rm := newMonitorWithFakeMaps(t, nil, newFakeBPFMap(), eventChan)
	limit := &ResourceLimit{LimitBytes: 100, UsageBytes: 30, ResourceType: ResourceMemory}
	rm.sendResourceEvent(ResourceMemory, "memory", limit, 30, AlertNone)
	rm.sendResourceEvent(ResourceMemory, "memory", limit, 90, AlertCritical)
}

func resourceGaugeSeries(t *testing.T, namespace, pod string) int {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, family := range families {
		if family.GetName() != "podtrace_resource_utilization_percent" {
			continue
		}
		for _, m := range family.GetMetric() {
			if labelValue(m, "namespace") == namespace && labelValue(m, "pod") == pod {
				n++
			}
		}
	}
	return n
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func monitorWithMemory(t *testing.T, namespace, pod string) *ResourceMonitor {
	t.Helper()
	rm := newMonitorWithFakeMaps(t, nil, newFakeBPFMap(), nil)
	rm.SetPodIdentity(pod, namespace)
	rm.mu.Lock()
	rm.limits = map[uint32]*ResourceLimit{
		ResourceMemory: {LimitBytes: 100, UsageBytes: 50, ResourceType: ResourceMemory},
	}
	rm.mu.Unlock()
	rm.checkAlerts()
	return rm
}

func TestPodsInOneNamespaceKeepTheirOwnResourceSeries(t *testing.T) {
	a := monitorWithMemory(t, "gauge-shared-ns", "pod-a")
	b := monitorWithMemory(t, "gauge-shared-ns", "pod-b")
	if resourceGaugeSeries(t, "gauge-shared-ns", "pod-a") != 1 || resourceGaugeSeries(t, "gauge-shared-ns", "pod-b") != 1 {
		t.Fatal("two pods in one namespace must not share a series")
	}

	a.Stop()
	if resourceGaugeSeries(t, "gauge-shared-ns", "pod-a") != 0 {
		t.Fatal("a stopped monitor's series must be removed")
	}
	if resourceGaugeSeries(t, "gauge-shared-ns", "pod-b") != 1 {
		t.Fatal("stopping one pod's monitor removed another pod's series")
	}
	b.Stop()
}

func TestLearningThePodRemovesTheSeriesExportedWithoutIt(t *testing.T) {
	rm := monitorWithMemory(t, "gauge-identity-ns", "")
	if resourceGaugeSeries(t, "gauge-identity-ns", "") != 1 {
		t.Fatal("expected a series before the pod was known")
	}
	rm.SetPodIdentity("pod-c", "gauge-identity-ns")
	if resourceGaugeSeries(t, "gauge-identity-ns", "") != 0 {
		t.Fatal("the series without a pod outlived the pod becoming known")
	}
	rm.SetPodIdentity("pod-c", "gauge-identity-ns")
}

func TestNamingAMonitorThatNeverExportedLeavesOtherSeriesAlone(t *testing.T) {
	other := monitorWithMemory(t, "gauge-quiet-ns", "")
	quiet := newMonitorWithFakeMaps(t, nil, newFakeBPFMap(), nil)
	quiet.SetPodIdentity("", "gauge-quiet-ns")
	quiet.SetPodIdentity("pod-d", "gauge-quiet-ns")
	quiet.Stop()
	if resourceGaugeSeries(t, "gauge-quiet-ns", "") != 1 {
		t.Fatal("a monitor that never exported removed another monitor's series")
	}
	other.Stop()
}
