package diagnose

import (
	"math"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func kernelRow(cgroup uint64, typ events.EventType, latencyNS, count uint64) kernelagg.Row {
	return kernelagg.Row{
		Key:   kernelagg.Key{CgroupID: cgroup, EventType: uint8(typ), Bucket: kernelagg.BucketIndex(latencyNS)},
		Value: kernelagg.Value{Count: count, SumNS: latencyNS * count, Bytes: 10 * count},
	}
}

func TestOnlyTheCgroupsAPodsEventsCameFromAreCounted(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, CgroupID: 7})
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.AddFastFilesystemOps([]kernelagg.Row{
		kernelRow(7, events.EventRead, 50_000, 30),
		kernelRow(7, events.EventRead, 400_000, 2),
		kernelRow(7, events.EventFsync, 600_000, 1),
		kernelRow(7, events.EventOpen, 10_000, 99),
		kernelRow(8, events.EventWrite, 50_000, 40),
	})

	got := d.FastFilesystemOps()
	if len(got) != 2 {
		t.Fatalf("counts = %+v, want reads and fsyncs of cgroup 7 only", got)
	}
	r := got[events.EventRead]
	if r.Count != 32 || r.Bytes != 320 || r.SumNS != 30*50_000+2*400_000 || len(r.Buckets) != 2 {
		t.Errorf("reads = %+v", r)
	}
	if len(d.FastFilesystemRows()) != 5 {
		t.Errorf("rows kept = %d, want all five for the per-pod diagnosticians", len(d.FastFilesystemRows()))
	}
}

func TestNoRowsOrNoMatchingCgroupMeansNoCounts(t *testing.T) {
	d := NewDiagnostician()
	if d.FastFilesystemOps() != nil {
		t.Error("counts without any rows")
	}
	d.AddEvent(&events.Event{Type: events.EventDNS, CgroupID: 1})
	d.AddFastFilesystemOps([]kernelagg.Row{kernelRow(2, events.EventRead, 50_000, 3)})
	if d.FastFilesystemOps() != nil {
		t.Error("another cgroup's rows were counted")
	}
}

func TestAKernelBucketsUpperBoundIsInMilliseconds(t *testing.T) {
	got := kernelBucketUpperMs(kernelagg.BucketIndex(1_000_000))
	if got < 1 || got > math.Exp2(1.0/8) {
		t.Errorf("the 1ms bucket's upper bound = %vms, want at or just above 1ms", got)
	}
}
