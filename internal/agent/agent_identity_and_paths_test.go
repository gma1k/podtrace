package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestSetIdentityPublishesNodeAndFleet(t *testing.T) {
	m := NewMetrics()
	m.SetIdentity("kind-worker", "default")

	ch := make(chan prometheus.Metric, 8)
	go func() {
		m.AgentInfo.Collect(ch)
		close(ch)
	}()

	var found bool
	for metric := range ch {
		var pb dto.Metric
		if err := metric.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["node"] == "kind-worker" && labels["tracer_config"] == "default" {
			found = true
		}
	}
	if !found {
		t.Error("SetIdentity published no series carrying node and tracer_config. Two " +
			"overlapping fleets scrape into the same Prometheus, and without this a series " +
			"cannot be attributed to either")
	}
}

func TestSetIdentityOnANilMetricsIsInert(t *testing.T) {
	var m *Metrics
	m.SetIdentity("node", "fleet")

	empty := &Metrics{}
	empty.SetIdentity("node", "fleet")
}

func TestKernelDroppedTotalReportsWhatWasRecorded(t *testing.T) {
	var nilMetrics *Metrics
	if got := nilMetrics.KernelDroppedTotal(); got != 0 {
		t.Errorf("nil Metrics reported %d drops, want 0", got)
	}

	m := NewMetrics()
	if got := m.KernelDroppedTotal(); got != 0 {
		t.Errorf("fresh Metrics reported %d drops, want 0", got)
	}
	m.kernelDropped.Store(42)
	if got := m.KernelDroppedTotal(); got != 42 {
		t.Errorf("KernelDroppedTotal = %d, want 42; this feeds the per-node CR status, so a "+
			"wrong reading hides kernel event loss from the operator", got)
	}
}

func TestMetricsPlaneCategoriesIsTheExportedViewOfThePrivateSet(t *testing.T) {
	exported := MetricsPlaneCategories()
	internal := metricsPlaneCategories()

	if len(exported) != len(internal) {
		t.Fatalf("exported %v but internally %v", exported, internal)
	}
	for i := range internal {
		if exported[i] != internal[i] {
			t.Fatalf("exported %v, want %v", exported, internal)
		}
	}
	if len(exported) == 0 {
		t.Fatal("the plane enables no categories, so it would measure nothing")
	}
	for _, c := range exported {
		if c == "fs" {
			t.Error("the plane enables the filesystem category. Measured on kind it was 94.9% " +
				"of all observations and saturated the agent's CPU limit, which is why it is " +
				"deliberately excluded")
		}
	}
}

func TestCgroupIDFromPathReturnsTheInode(t *testing.T) {
	dir := t.TempDir()
	id, err := cgroupIDFromPath(dir)
	if err != nil {
		t.Fatalf("cgroupIDFromPath: %v", err)
	}
	if id == 0 {
		t.Error("inode 0 for a real directory; the kernel reports this value on every eBPF " +
			"event, so a zero would match no target")
	}

	if _, err := cgroupIDFromPath(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("a missing cgroup path returned no error")
	}
}

func TestResolveNodeNamePrefersTheEnvironment(t *testing.T) {
	t.Setenv("NODE_NAME", "  kind-worker2  ")
	if got := ResolveNodeName(); got != "kind-worker2" {
		t.Errorf("ResolveNodeName = %q, want kind-worker2 trimmed", got)
	}

	t.Setenv("NODE_NAME", "   ")
	host, err := os.Hostname()
	if err != nil {
		t.Skip("no hostname available")
	}
	if got := ResolveNodeName(); got != host {
		t.Errorf("ResolveNodeName = %q, want the hostname %q; a blank NODE_NAME must fall back "+
			"rather than leave every metric and CR status unattributed", got, host)
	}
}
