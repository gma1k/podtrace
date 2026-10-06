package inspect

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func fsOps(operation string, total, withinBound uint64) *dto.Metric {
	return bucketHistogram(total, 1, []*dto.Bucket{
		bucket(0.001, withinBound/2),
		bucket(0.05, withinBound),
		bucket(30, total),
	}, workloadLabels(label("operation", operation))...)
}

func fsFamily(metrics ...*dto.Metric) []*dto.MetricFamily {
	return []*dto.MetricFamily{histogramFamily(familyFSLatency, metrics...)}
}

func TestSlowFilesystemFiresWhenTooManyOperationsExceedTheBound(t *testing.T) {
	got := evalOnce(t, fsSlowOperationsRule(), nil, fsFamily(fsOps("read", 900, 900), fsOps("fsync", 100, 0)), time.Minute)
	if len(got) != 1 || got[0].ID != detector.IDFSSlowOperations {
		t.Fatalf("issues = %v, want one fs.slow_operations at a 10%% slow share", got)
	}
	if !strings.Contains(got[0].Message, "10.0% of 1000 reads, writes and fsyncs took longer than 50ms") {
		t.Errorf("message = %q", got[0].Message)
	}
	if !strings.Contains(got[0].Remediation, "volume") {
		t.Errorf("remediation does not send the operator to the storage: %q", got[0].Remediation)
	}
}

func TestSlowFilesystemStaysQuietAtTheIdleFloor(t *testing.T) {
	if got := evalOnce(t, fsSlowOperationsRule(), nil, fsFamily(fsOps("read", 10000, 10000), fsOps("write", 500, 500)), time.Minute); len(got) != 0 {
		t.Errorf("fired with no operation above the bound: %v", got)
	}
}

func TestSlowFilesystemIgnoresOpensAndCloses(t *testing.T) {
	cur := fsFamily(fsOps("read", 1000, 1000), fsOps("open", 1000, 0), fsOps("close", 1000, 0))
	if got := evalOnce(t, fsSlowOperationsRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("slow opens and closes fired a rule about reads, writes and fsyncs: %v", got)
	}
}

func TestSlowFilesystemStaysQuietBelowTheTrafficFloor(t *testing.T) {
	if got := evalOnce(t, fsSlowOperationsRule(), nil, fsFamily(fsOps("fsync", 5, 0)), time.Minute); len(got) != 0 {
		t.Errorf("five slow fsyncs in a minute, under the 0.1/s floor, fired: %v", got)
	}
}

func TestSlowFilesystemStaysSilentWhenTheBoundIsNotABucketBoundary(t *testing.T) {
	cur := fsFamily(bucketHistogram(1000, 50, []*dto.Bucket{bucket(0.001, 100), bucket(30, 1000)},
		workloadLabels(label("operation", "read"))...))
	if got := evalOnce(t, fsSlowOperationsRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("reported a share the histogram cannot support: %v", got)
	}
}

func TestSlowFilesystemReadsAKernelAggregatedNativeHistogram(t *testing.T) {
	m := nativeHistogram(1000, 30, 0, []nativeSpan{{-80, 1}, {74, 1}}, []int64{800, -600})
	m.Label = append(m.Label, label("operation", "write"))
	got := evalOnce(t, fsSlowOperationsRule(), nil, []*dto.MetricFamily{histogramFamily(familyFSLatency, m)}, time.Minute)
	if len(got) != 1 || !strings.Contains(got[0].Message, "20.0%") {
		t.Fatalf("issues = %v, want 200 of 1000 writes above the bound", got)
	}
}

func TestSlowFilesystemIgnoresAResetAndIsOffWithoutABound(t *testing.T) {
	if got := evalOnce(t, fsSlowOperationsRule(), fsFamily(fsOps("read", 5000, 5000)), fsFamily(fsOps("read", 1000, 0)), time.Minute); len(got) != 0 {
		t.Errorf("a counter reset was read as operations: %v", got)
	}
	start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	before, _ := Take(&fixedGatherer{}, start)
	after, _ := Take(&fixedGatherer{families: fsFamily(fsOps("read", 1000, 0))}, start.Add(time.Minute))
	th := DefaultThresholds()
	th.FSSlowBound = 0
	if got := fsSlowOperationsRule().Eval(Window{Prev: before, Cur: after}, th); len(got) != 0 {
		t.Errorf("fired with no bound: %v", got)
	}
	if got := fsSlowOperationsRule().Eval(Window{Cur: after}, DefaultThresholds()); len(got) != 0 {
		t.Errorf("fired from a single snapshot: %v", got)
	}
}
