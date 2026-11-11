package diagnose

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

func withMemoryLimit(t *testing.T, limit int64, ok bool) {
	t.Helper()
	orig := containerMemoryLimit
	containerMemoryLimit = func() (int64, bool) { return limit, ok }
	t.Cleanup(func() { containerMemoryLimit = orig })
}

func TestTheBufferHoldsWhatTheMemoryLimitAllows(t *testing.T) {
	for _, tc := range []struct {
		limit int64
		want  int
	}{
		{1 << 30, 524_288},
		{512 << 20, 262_144},
		{1 << 20, minimumEventCapacity},
		{64 << 30, config.MaxEvents},
	} {
		if got := eventCapacityFor(tc.limit); got != tc.want {
			t.Errorf("capacity under %d MiB = %d, want %d", tc.limit>>20, got, tc.want)
		}
	}
}

func TestADiagnosticianWithoutAMemoryLimitKeepsTheFullBuffer(t *testing.T) {
	withMemoryLimit(t, 0, false)
	if got := NewDiagnostician().EventCapacity(); got != config.MaxEvents {
		t.Errorf("capacity = %d, want %d", got, config.MaxEvents)
	}
}

func TestADiagnosticianUnderAMemoryLimitSizesItsBuffer(t *testing.T) {
	withMemoryLimit(t, 1<<30, true)
	for _, d := range []*Diagnostician{NewDiagnostician(), NewDiagnosticianWithThresholds(10, 100, 10), NewDiagnosticianWithK8sAndThresholds("p", "n", 10, 100, 10)} {
		if got, want := d.EventCapacity(), eventCapacityFor(1<<30); got != want {
			t.Errorf("capacity = %d, want %d", got, want)
		}
	}
}

func TestTheReportSaysWhenTheBufferWasSizedDown(t *testing.T) {
	withMemoryLimit(t, 4<<20, true)
	d := NewDiagnostician()
	d.sampleIntN = reject
	for i := 0; i < minimumEventCapacity+5; i++ {
		d.AddEvent(&events.Event{Type: events.EventTCPRecv})
	}
	got := report.GenerateSummarySection(d, time.Second)
	want := fmt.Sprintf("The buffer held %d events rather than %d", minimumEventCapacity, config.MaxEvents)
	if !strings.Contains(got, want) {
		t.Errorf("summary = %q, want %q", got, want)
	}

	withMemoryLimit(t, 0, false)
	full := NewDiagnostician()
	full.maxEvents = config.MaxEvents
	full.droppedEvents = 1
	if got := report.GenerateSummarySection(full, time.Second); strings.Contains(got, "rather than") {
		t.Errorf("summary = %q mentions a smaller buffer at full capacity", got)
	}
}

func TestABufferedEventCostsNoMoreThanItsBudget(t *testing.T) {
	withMemoryLimit(t, 0, false)
	const n = 200_000
	shared := &events.K8sMetadata{Namespace: "shop", PodName: "api", ContainerName: "app"}
	ctx := map[string]interface{}{"namespace": "shop", "target_pod": "db-0", "target_namespace": "shop", "is_external": false}
	comm := []byte("python3")
	target := []byte("10.244.1.7:7000")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	d := NewDiagnostician()
	for i := 0; i < n; i++ {
		d.AddEventWithContext(&events.Event{
			Type: events.EventTCPRecv, PID: 1234, Error: -11, CgroupID: 77, LatencyNS: 10_000,
			Timestamp: uint64(i), ProcessName: string(comm), Target: string(target), K8s: shared,
		}, ctx)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	perEvent := (safeconv.Uint64ToInt64(after.HeapAlloc) - safeconv.Uint64ToInt64(before.HeapAlloc)) / n
	if perEvent > bufferedEventBytes {
		t.Errorf("a buffered event retained %d bytes, above the %d the capacity is sized by", perEvent, bufferedEventBytes)
	}
	runtime.KeepAlive(d)
}
