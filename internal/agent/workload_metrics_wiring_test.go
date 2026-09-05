package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func exporterNames(t *testing.T) []string {
	t.Helper()

	metrics := NewMetrics()
	exporters, _, err := buildExporters(NewRouter(nil), metrics, nil, nil, logr.Discard())
	if err != nil {
		t.Fatalf("buildExporters: %v", err)
	}

	names := make([]string, 0, len(exporters))
	for _, e := range exporters {
		names = append(names, e.Name())
	}
	return names
}

func TestWorkloadMetricsPlaneAbsentByDefault(t *testing.T) {
	original := config.WorkloadMetricsEnabled
	config.WorkloadMetricsEnabled = false
	t.Cleanup(func() { config.WorkloadMetricsEnabled = original })

	names := exporterNames(t)
	if len(names) != 1 || names[0] != "cr-router" {
		t.Fatalf("exporters = %v, want only the CR router when the plane is off", names)
	}
}

func TestWorkloadMetricsPlaneJoinsTheFanOutWhenEnabled(t *testing.T) {
	originalEnabled := config.WorkloadMetricsEnabled
	originalBudget := config.WorkloadMetricsBudget
	config.WorkloadMetricsEnabled = true
	config.WorkloadMetricsBudget = 100
	t.Cleanup(func() {
		config.WorkloadMetricsEnabled = originalEnabled
		config.WorkloadMetricsBudget = originalBudget
	})

	names := exporterNames(t)
	if len(names) != 2 {
		t.Fatalf("exporters = %v, want the router plus the metrics plane", names)
	}
	if names[0] != "cr-router" {
		t.Errorf("exporters[0] = %q, want the router first", names[0])
	}
	if names[1] != "workload-metrics" {
		t.Errorf("exporters[1] = %q, want workload-metrics", names[1])
	}
}

func TestWorkloadMetricsRegistersOnTheAgentEndpoint(t *testing.T) {
	originalEnabled := config.WorkloadMetricsEnabled
	config.WorkloadMetricsEnabled = true
	t.Cleanup(func() { config.WorkloadMetricsEnabled = originalEnabled })

	metrics := NewMetrics()
	if _, _, err := buildExporters(NewRouter(nil), metrics, nil, nil, logr.Discard()); err != nil {
		t.Fatalf("buildExporters: %v", err)
	}

	families, err := metrics.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	var found bool
	for _, f := range families {
		if strings.HasPrefix(f.GetName(), "podtrace_workload_") {
			found = true
			break
		}
	}
	if !found {
		t.Error("no podtrace_workload_* family on the agent registry; the plane " +
			"must register where the agent already serves /metrics, not on the " +
			"global default registry the CLI owns")
	}
}

func TestBuildExportersRejectsDoubleRegistration(t *testing.T) {
	originalEnabled := config.WorkloadMetricsEnabled
	config.WorkloadMetricsEnabled = true
	t.Cleanup(func() { config.WorkloadMetricsEnabled = originalEnabled })

	metrics := NewMetrics()
	if _, _, err := buildExporters(NewRouter(nil), metrics, nil, nil, logr.Discard()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, _, err := buildExporters(NewRouter(nil), metrics, nil, nil, logr.Discard()); err == nil {
		t.Error("registering the plane twice on one registry must fail rather than " +
			"silently serving one of two copies")
	}
}

func TestEnricherLookupIsWiredWhenAnEnricherExists(t *testing.T) {
	if enricherLookup(nil) != nil {
		t.Error("a nil enricher must yield a nil lookup so the plane reports " +
			"unattributed rather than panicking")
	}

	enricher := NewPodEnricher()
	enricher.Snapshot([]PodCgroupEntry{{
		Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "checkout"},
		},
		ContainerName: "app",
		CgroupID:      99,
	}})

	lookup := enricherLookup(enricher)
	if lookup == nil {
		t.Fatal("a real enricher must yield a usable lookup")
	}
	meta, ok := lookup(99)
	if !ok {
		t.Fatal("lookup missed a cgroup the enricher holds")
	}
	if meta.Namespace != "shop" {
		t.Errorf("namespace = %q, want shop", meta.Namespace)
	}
}

func TestBudgetExhaustionLogCallbackIsInstalled(t *testing.T) {
	originalEnabled := config.WorkloadMetricsEnabled
	originalBudget := config.WorkloadMetricsBudget
	config.WorkloadMetricsEnabled = true
	config.WorkloadMetricsBudget = 1
	t.Cleanup(func() {
		config.WorkloadMetricsEnabled = originalEnabled
		config.WorkloadMetricsBudget = originalBudget
	})

	exporters, _, err := buildExporters(NewRouter(nil), NewMetrics(), nil, nil, logr.Discard())
	if err != nil {
		t.Fatalf("buildExporters: %v", err)
	}

	sink := exporters[len(exporters)-1]
	batch := make([]*events.Event, 0, 3)
	for _, workload := range []string{"a", "b", "c"} {
		batch = append(batch, &events.Event{
			Type:      events.EventDNS,
			LatencyNS: 1_000_000,
			K8s: &events.K8sMetadata{
				Namespace:    "shop",
				WorkloadName: workload,
			},
		})
	}

	// Drives the sink past its budget so the exhaustion callback the agent
	// installs actually runs. Without this the callback is dead wiring: it
	// would only ever fire in production, which is the worst place to
	// discover a nil-pointer or a bad format string.
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
}

func TestAgentEndpointExposesItsOwnResourceUse(t *testing.T) {
	// The continuous metrics plane can drive the agent to its CPU limit,
	// where it is throttled and the workload metrics silently
	// under-report. Diagnosing that without these collectors meant
	// shelling into a node and running crictl, so their absence is an
	// operability defect rather than a missing nicety.
	families, err := NewMetrics().registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	present := map[string]bool{}
	for _, f := range families {
		present[f.GetName()] = true
	}

	for _, want := range []string{
		"process_cpu_seconds_total",
		"process_resident_memory_bytes",
		"go_goroutines",
	} {
		if !present[want] {
			t.Errorf("%s missing from the agent registry; docs/continuous-metrics.md "+
				"tells operators to alert on it", want)
		}
	}
}
