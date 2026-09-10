package inspect

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Inspections read metrics, not events.
type Sample struct {
	Namespace    string
	Workload     string
	WorkloadKind string
	Container    string
	Pod          string

	Labels map[string]string

	Value float64

	Count uint64
	Sum   float64
}

// Label returns one family-specific label, empty when absent.
func (s Sample) Label(name string) string { return s.Labels[name] }

// Snapshot is one gather, indexed by metric family.
type Snapshot struct {
	At       time.Time
	families map[string][]Sample
}

func (s Snapshot) Family(name string) []Sample { return s.families[name] }

func (s Snapshot) IsZero() bool { return s.At.IsZero() }

// FamilySource yields the current metrics of named families only.
type FamilySource interface {
	CollectFamilies(names []string) map[string][]*dto.Metric
	RuleFamilies() []string
}

// TakeFrom builds a snapshot from a FamilySource, touching only the families
// the rules actually read.
func TakeFrom(src FamilySource, now time.Time) Snapshot {
	names := src.RuleFamilies()
	families := src.CollectFamilies(names)

	snap := Snapshot{At: now, families: make(map[string][]Sample, len(families))}
	for name, metrics := range families {
		samples := make([]Sample, 0, len(metrics))
		for _, m := range metrics {
			samples = append(samples, sampleOf(m))
		}
		snap.families[name] = samples
	}
	return snap
}

// Take gathers the registry into a snapshot. Prefer TakeFrom where a
// FamilySource is available.
func Take(g prometheus.Gatherer, now time.Time) (Snapshot, error) {
	families, err := g.Gather()
	if err != nil {
		if len(families) == 0 {
			return Snapshot{}, err
		}
	}

	snap := Snapshot{At: now, families: make(map[string][]Sample, len(families))}
	for _, f := range families {
		name := f.GetName()
		samples := make([]Sample, 0, len(f.GetMetric()))
		for _, m := range f.GetMetric() {
			samples = append(samples, sampleOf(m))
		}
		snap.families[name] = samples
	}
	return snap, err
}

// sampleOf reduces one gathered metric to a Sample.
func sampleOf(m *dto.Metric) Sample {
	s := Sample{Labels: map[string]string{}}
	for _, pair := range m.GetLabel() {
		name, value := pair.GetName(), pair.GetValue()
		switch name {
		case "namespace":
			s.Namespace = value
		case "workload":
			s.Workload = value
		case "workload_kind":
			s.WorkloadKind = value
		case "container":
			s.Container = value
		case "pod":
			s.Pod = value
		default:
			s.Labels[name] = value
		}
	}

	switch {
	case m.GetCounter() != nil:
		s.Value = m.GetCounter().GetValue()
	case m.GetGauge() != nil:
		s.Value = m.GetGauge().GetValue()
	case m.GetHistogram() != nil:
		h := m.GetHistogram()
		s.Count = h.GetSampleCount()
		s.Sum = h.GetSampleSum()
		s.Value = h.GetSampleSum()
	case m.GetUntyped() != nil:
		s.Value = m.GetUntyped().GetValue()
	}
	return s
}

// seriesKey identifies a series across snapshots so a delta can be taken.
func seriesKey(s Sample) string {
	key := s.Namespace + "\x00" + s.Workload + "\x00" + s.WorkloadKind +
		"\x00" + s.Container + "\x00" + s.Pod
	for _, name := range sortedKeys(s.Labels) {
		key += "\x00" + name + "=" + s.Labels[name]
	}
	return key
}
