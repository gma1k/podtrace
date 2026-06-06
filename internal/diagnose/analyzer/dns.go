package analyzer

import (
	"sort"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

// AnalyzeDNS aggregates DNS activity. Names and per-name lookup counts come
// from queries (every lookup, reliable even without a response); latency,
// response codes (errors) and percentiles come from responses. If no queries
// were captured (egress missed but the response was seen), responses are used
// for the target list too.
func AnalyzeDNS(queries, responses []*events.Event) (avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []TargetCount) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	errors = 0

	for _, e := range responses {
		latencyMs := float64(e.LatencyNS) / float64(config.NSPerMS)
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if latencyMs > maxLatency {
			maxLatency = latencyMs
		}
		if e.Error != 0 {
			errors++
		}
	}

	if len(responses) > 0 {
		avgLatency = totalLatency / float64(len(responses))
		sort.Float64s(latencies)
		p50 = Percentile(latencies, 50)
		p95 = Percentile(latencies, 95)
		p99 = Percentile(latencies, 99)
	}

	nameSource := queries
	if len(nameSource) == 0 {
		nameSource = responses
	}
	targetMap := make(map[string]int)
	for _, e := range nameSource {
		if e.Target != "" && e.Target != "?" {
			targetMap[e.Target]++
		}
	}
	for target, count := range targetMap {
		topTargets = append(topTargets, TargetCount{target, count})
	}
	sort.Slice(topTargets, func(i, j int) bool {
		return topTargets[i].Count > topTargets[j].Count
	})

	return
}
