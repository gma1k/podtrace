package agent

import (
	"reflect"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestContinuousProfilingAloneStillCoversTheNodeForCPU(t *testing.T) {
	coverage := NodeCoverage(false, true, []string{"podtrace-system"})
	if !coverage.Enabled {
		t.Fatal("profiling on with metrics off covered no pods.\n\nThe profiler builds its " +
			"profiles from the sched_switch stacks of every local pod. With coverage keyed " +
			"on the metrics plane alone, turning metrics off left /profile returning an " +
			"empty list while continuousProfiling said true.")
	}
	if got := StartupCategories(coverage); !reflect.DeepEqual(got, []string{string(podtracev1alpha1.FilterCPU)}) {
		t.Errorf("startup categories = %v, want only cpu: profiling needs sched_switch and "+
			"nothing else, so dns and net would be cost for no reader", got)
	}
}

func TestMetricsCoverageKeepsItsFullCategorySet(t *testing.T) {
	for _, profiling := range []bool{false, true} {
		got := StartupCategories(NodeCoverage(true, profiling, nil))
		if !reflect.DeepEqual(got, metricsPlaneCategories()) {
			t.Errorf("profiling=%v: categories = %v, want the metrics plane's %v", profiling, got, metricsPlaneCategories())
		}
	}
}

func TestWithBothOffNothingIsCoveredNodeWide(t *testing.T) {
	coverage := NodeCoverage(false, false, nil)
	if coverage.Enabled || len(StartupCategories(coverage)) != 0 {
		t.Errorf("coverage %+v attached categories with every continuous feature off", coverage)
	}
}

func TestAProfilingOnlyNodeMergesCPUIntoWhatPodTracesAsk(t *testing.T) {
	got := unionCategories([]string{"fs"}, NodeCoverage(false, true, nil))
	if !reflect.DeepEqual(got, []string{"cpu", "fs"}) {
		t.Errorf("union = %v, want [cpu fs]", got)
	}
}

func TestAProfilingOnlyNodeTargetsEveryLocalPod(t *testing.T) {
	entries := []PodCgroupEntry{
		podEntry("shop", "checkout", "app", 1),
		podEntry("podtrace-system", "agent", "agent", 2),
	}
	got := expandTargetsForMetricsPlane(nil, entries, NodeCoverage(false, true, []string{"podtrace-system"}))
	if keys := targetKeys(got); len(keys) != 1 || keys[0] != targetIdentity("shop", "checkout", "app") {
		t.Errorf("targets = %v, want only shop/checkout: profiling alone must still cover the "+
			"node's pods, minus the excluded namespaces", keys)
	}
}
