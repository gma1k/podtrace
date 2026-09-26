package workloadmetrics

import (
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

const preemptedVariant = uint8(schedPreempted)

func TestAKernelAggregatedPreemptionReachesTheRunqueueFamily(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventSchedSwitch, preemptedVariant,
			kernelagg.BucketIndex(110_000_000), 40, 40*110_000_000, 0),
	})

	if got := gather(t, reg, "podtrace_workload_cpu_runqueue_latency_seconds"); len(got) != 1 {
		t.Fatalf("got %d run-queue series from a preempted kernel row, want 1.\n\nThe "+
			"preemption flag rides in the aggregation variant. If this path drops it, "+
			"cpu.contention reads nothing wherever kernel aggregation is on, which is "+
			"the mode meant for production.", len(got))
	}
	if got := gather(t, reg, "podtrace_workload_cpu_blocked_seconds"); len(got) != 1 {
		t.Errorf("a preempted interval is still time off the CPU and must also land in "+
			"cpu_blocked_seconds; got %d series", len(got))
	}
}

func TestAKernelAggregatedVoluntarySleepStaysOutOfTheRunqueueFamily(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventSchedSwitch, 0,
			kernelagg.BucketIndex(2_800_000_000), 10, 10*2_800_000_000, 0),
	})

	if got := gather(t, reg, "podtrace_workload_cpu_runqueue_latency_seconds"); len(got) != 0 {
		t.Errorf("a voluntary sleep produced %d run-queue series.\n\nThat is an idle "+
			"pod parked in epoll_wait, and counting it is the exact inversion the "+
			"run-queue family exists to avoid.", len(got))
	}
	if got := gather(t, reg, "podtrace_workload_cpu_blocked_seconds"); len(got) != 1 {
		t.Errorf("the sleep must still be counted as off-CPU time; got %d series", len(got))
	}
}
