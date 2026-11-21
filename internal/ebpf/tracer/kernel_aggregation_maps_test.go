package tracer

import (
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

func kernelAggMaps(t *testing.T, names ...string) *ebpf.Collection {
	t.Helper()
	specs := map[string]*ebpf.MapSpec{
		kernelagg.MapName:        {Type: ebpf.LRUCPUHash, KeySize: 40, ValueSize: 24, MaxEntries: 16},
		kernelagg.EnabledMapName: {Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
		kernelagg.ConfigMapName:  {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
		kernelagg.StatsMapName:   {Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 2},
	}
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{}}
	t.Cleanup(coll.Close)
	for _, name := range names {
		m, err := ebpf.NewMap(specs[name])
		if err != nil {
			t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
		}
		coll.Maps[name] = m
	}
	return coll
}

func readAggConfig(t *testing.T, coll *ebpf.Collection) kernelagg.Config {
	t.Helper()
	var cfg kernelagg.Config
	if err := coll.Maps[kernelagg.ConfigMapName].Lookup(uint32(0), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestTurningAggregationOnWritesTheRowBudget(t *testing.T) {
	orig := config.WorkloadMetricsContainerRowBudget
	config.WorkloadMetricsContainerRowBudget = 77
	t.Cleanup(func() { config.WorkloadMetricsContainerRowBudget = orig })
	tr := &Tracer{collection: kernelAggMaps(t, kernelagg.EnabledMapName, kernelagg.ConfigMapName)}

	if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
		t.Fatal(err)
	}
	if got := readAggConfig(t, tr.collection).CgroupRowBudget; got != 77 {
		t.Fatalf("row budget = %d, want 77", got)
	}

	config.WorkloadMetricsContainerRowBudget = 5
	if err := tr.SetKernelAggregationMode(kernelagg.ModeOff); err != nil {
		t.Fatal(err)
	}
	if got := readAggConfig(t, tr.collection).CgroupRowBudget; got != 77 {
		t.Errorf("turning aggregation off rewrote the budget to %d", got)
	}
}

func TestAMissingOrBrokenConfigMapDoesNotBlockAggregation(t *testing.T) {
	tr := &Tracer{collection: kernelAggMaps(t, kernelagg.EnabledMapName)}
	if err := tr.SetKernelAggregationMode(kernelagg.ModeOn); err != nil {
		t.Fatalf("no config map: %v", err)
	}

	broken := kernelAggMaps(t, kernelagg.EnabledMapName, kernelagg.ConfigMapName)
	_ = broken.Maps[kernelagg.ConfigMapName].Close()
	tr = &Tracer{collection: broken}
	if err := tr.SetKernelAggregationMode(kernelagg.ModeOn); err != nil {
		t.Fatalf("a budget that cannot be written failed the mode switch: %v", err)
	}
}

func TestADrainStartsANewBudgetIntervalAndTracksPressure(t *testing.T) {
	coll := kernelAggMaps(t, kernelagg.MapName, kernelagg.ConfigMapName, kernelagg.StatsMapName)
	nCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	created := make([]uint64, nCPU)
	created[0] = 3
	collapsed := make([]uint64, nCPU)
	collapsed[0] = 2
	if err := coll.Maps[kernelagg.StatsMapName].Put(uint32(0), created); err != nil {
		t.Fatal(err)
	}
	if err := coll.Maps[kernelagg.StatsMapName].Put(uint32(1), collapsed); err != nil {
		t.Fatal(err)
	}
	row := make([]kernelagg.Value, nCPU)
	row[0] = kernelagg.Value{Count: 1}
	if err := coll.Maps[kernelagg.MapName].Put(kernelagg.Key{CgroupID: 9}, row); err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{collection: coll}

	rows, err := tr.DrainKernelMetrics()
	if err != nil || len(rows) != 1 {
		t.Fatalf("drain = %v, %v", rows, err)
	}
	if got := readAggConfig(t, coll).Generation; got != 1 {
		t.Errorf("generation = %d after one drain, want 1", got)
	}
	if got := tr.KernelAggregationPressure(); got != (kernelagg.Pressure{RowsEvicted: 2, PeerCollapsed: 2}) {
		t.Errorf("pressure = %+v; 3 rows were created and the drain found 1", got)
	}
}

func TestADrainWithoutTheBudgetMapsStillDrains(t *testing.T) {
	coll := kernelAggMaps(t, kernelagg.MapName, kernelagg.ConfigMapName)
	_ = coll.Maps[kernelagg.ConfigMapName].Close()
	tr := &Tracer{collection: coll}

	if _, err := tr.DrainKernelMetrics(); err != nil {
		t.Fatalf("drain failed without the stats map and with a broken config map: %v", err)
	}
	if got := tr.KernelAggregationPressure(); got != (kernelagg.Pressure{}) {
		t.Errorf("pressure = %+v without stats", got)
	}
}

func TestKernelAggregationPressureOnANilTracer(t *testing.T) {
	var tr *Tracer
	if got := tr.KernelAggregationPressure(); got != (kernelagg.Pressure{}) {
		t.Errorf("pressure = %+v", got)
	}
}
