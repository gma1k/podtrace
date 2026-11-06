package tracer

import (
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/events"
)

func TestWithoutProcessCPUSnapshotsSetsTheStartupOption(t *testing.T) {
	var o tracerOptions
	WithoutProcessCPUSnapshots()(&o)
	if !o.withoutCPUSnapshots {
		t.Fatal("the option did not switch CPU snapshots off")
	}
}

func TestATracerWithoutCPUSnapshotsDoesNotReadProcPerEvent(t *testing.T) {
	_, base := nameTestTracer(t)
	fakeProcess(t, base, 4242, "worker", 100)
	cache.ResetCPUTimes()
	t.Cleanup(cache.ResetCPUTimes)

	off := newDispatchTestTracer()
	off.skipCPUSnapshots = true
	dispatchConfined(t, off, &events.Event{Type: events.EventTCPSend, PID: 4242, ProcessName: "worker"})
	if _, seen := cache.LookupCPUTime(4242); seen {
		t.Fatal("a tracer built without CPU snapshots still sampled /proc for an event")
	}

	on := newDispatchTestTracer()
	dispatchConfined(t, on, &events.Event{Type: events.EventTCPSend, PID: 4242, ProcessName: "worker"})
	if _, seen := cache.LookupCPUTime(4242); !seen {
		t.Fatal("the default tracer stopped sampling CPU time for the diagnose report")
	}
}
