package analyzer

import (
	"net"
	"sort"
	"strings"

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

// TargetAddrs pairs a DNS name with the distinct addresses it resolved to.
type TargetAddrs struct {
	Target string
	Addrs  []string
}

// ResolvedAddresses aggregates the resolved A/AAAA addresses seen per DNS name
// across response events.
func ResolvedAddresses(responses []*events.Event) []TargetAddrs {
	var order []string
	byName := make(map[string]*TargetAddrs)
	seen := make(map[string]map[string]struct{})
	for _, e := range responses {
		if e.Target == "" || e.Details == "" {
			continue
		}
		for _, addr := range strings.Split(e.Details, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" || net.ParseIP(addr) == nil {
				continue
			}
			ta, ok := byName[e.Target]
			if !ok {
				ta = &TargetAddrs{Target: e.Target}
				byName[e.Target] = ta
				seen[e.Target] = make(map[string]struct{})
				order = append(order, e.Target)
			}
			if _, dup := seen[e.Target][addr]; dup {
				continue
			}
			seen[e.Target][addr] = struct{}{}
			ta.Addrs = append(ta.Addrs, addr)
		}
	}
	out := make([]TargetAddrs, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Addrs) > len(out[j].Addrs)
	})
	return out
}
