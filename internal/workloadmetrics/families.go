package workloadmetrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/inspect"
)

// Reading a few families without serialising the whole registry.
func (s *Sink) CollectFamilies(names []string) map[string][]*dto.Metric {
	out := make(map[string][]*dto.Metric, len(names))
	for _, full := range names {
		collector, ok := s.collectorFor(full)
		if !ok {
			continue
		}
		if metrics := collectInto(collector); len(metrics) > 0 {
			out[full] = metrics
		}
	}
	return out
}

// RuleFamilies is the set of families the inspection rules read.
func (s *Sink) RuleFamilies() []string {
	return inspect.RuleFamilies()
}

// collectorFor resolves a full family name to the collector that owns it.
func (s *Sink) collectorFor(full string) (prometheus.Collector, bool) {
	short := strings.TrimPrefix(full, metricPrefix)
	if short == full {
		return nil, false
	}
	if s.kernelHist.owns(short) {
		return kernelFamilyCollector{k: s.kernelHist, family: short}, true
	}
	if h, ok := s.c.histogramFor(short); ok {
		return h, true
	}
	if v, ok := s.c.counterFor(short); ok {
		return v, true
	}
	if g, ok := s.c.sat.gaugeFor(short); ok {
		return g, true
	}
	return nil, false
}

// collectInto drains one collector's metrics.
func collectInto(c prometheus.Collector) []*dto.Metric {
	ch := make(chan prometheus.Metric, 64)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	var out []*dto.Metric
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			continue
		}
		out = append(out, &pb)
	}
	return out
}
