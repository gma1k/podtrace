//go:build bpf_loadtest && linux

package tracer

import (
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

func addLost(t *testing.T, coll *ebpf.Collection, reason uint32, n uint64) {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	perCPU := make([]uint64, cpus)
	if err := coll.Maps[oncpu.LostMapName].Lookup(reason, &perCPU); err != nil {
		t.Fatal(err)
	}
	perCPU[0] += n
	if err := coll.Maps[oncpu.LostMapName].Put(reason, perCPU); err != nil {
		t.Fatal(err)
	}
}

func TestKernelTheTracerReportsEachLostSampleOnceAcrossDrains(t *testing.T) {
	coll := onCPUCollection(t)
	tr := &Tracer{collection: coll}

	addLost(t, coll, oncpu.LostFull, 4)
	first, err := tr.DrainOnCPUSamples()
	if err != nil || first.Lost[oncpu.LostFull] != 4 {
		t.Fatalf("first drain lost = %v, %v; want 4", first.Lost, err)
	}

	second, err := tr.DrainOnCPUSamples()
	if err != nil || second.Lost[oncpu.LostFull] != 0 {
		t.Fatalf("second drain lost = %v, %v; samples lost before the first drain were counted again", second.Lost, err)
	}

	addLost(t, coll, oncpu.LostFull, 3)
	third, err := tr.DrainOnCPUSamples()
	if err != nil || third.Lost[oncpu.LostFull] != 3 {
		t.Fatalf("third drain lost = %v, %v; want only the 3 added since", third.Lost, err)
	}
}
