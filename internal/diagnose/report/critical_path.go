package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gma1k/podtrace/internal/analysis/criticalpath"
	"github.com/gma1k/podtrace/internal/sanitize"
)

// GenerateCriticalPathSection renders where the requests served during
// collection spent their time, or "" when no request finished.
func GenerateCriticalPathSection(s criticalpath.Summary, filter string) string {
	if s.Requests == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Request Time Breakdown:\n")
	fmt.Fprintf(&b, "  Requests served: %d (%s)\n", s.Requests, kindCounts(s.ByKind))
	fmt.Fprintf(&b, "  Where their time went: %s\n", formatShares(sharesOf(s.ByCategory), s.Total))
	if filter != "" {
		fmt.Fprintf(&b, "  Only waits in the filtered categories (%s) were kept; the rest of each request counts as not in traced I/O.\n", sanitize.Terminal(filter))
	}

	if len(s.ByEndpoint) > 0 {
		b.WriteString("  By endpoint, most total time first:\n")
		for i, e := range s.ByEndpoint {
			if i == endpointsShown {
				fmt.Fprintf(&b, "    ... %d more endpoints\n", len(s.ByEndpoint)-endpointsShown)
				break
			}
			mean := e.Total / time.Duration(e.Requests)
			fmt.Fprintf(&b, "    %s  %d requests, mean %v\n", sanitize.Terminal(e.Endpoint), e.Requests, roundForReading(mean))
			fmt.Fprintf(&b, "              %s\n", formatShares(sharesOf(e.ByCategory), e.Total))
		}
	}

	if len(s.Slowest) > 0 {
		b.WriteString("  Slowest requests:\n")
		for _, r := range s.Slowest {
			fmt.Fprintf(&b, "    %-9s %s\n", roundForReading(r.Latency), describe(r))
			fmt.Fprintf(&b, "              %s\n", formatShares(r.Shares, r.Latency))
		}
	}

	var gaps []string
	if s.Late > 0 {
		gaps = append(gaps, fmt.Sprintf("%d waits arrived after their request finished", s.Late))
	}
	if s.Evicted > 0 {
		gaps = append(gaps, fmt.Sprintf("%d requests were dropped unfinished", s.Evicted))
	}
	if s.Truncated > 0 {
		gaps = append(gaps, fmt.Sprintf("%d requests had more waits than were kept", s.Truncated))
	}
	if len(gaps) > 0 {
		fmt.Fprintf(&b, "  Not counted: %s\n", strings.Join(gaps, "; "))
	}
	b.WriteString("  Each stretch of a request is counted once, under its most specific wait, so the shares add up to the request.\n\n")
	return b.String()
}

// roundForReading keeps three or four significant digits: a sub-millisecond
// request rounded to 100µs would read as 0s.
func roundForReading(d time.Duration) time.Duration {
	switch {
	case d >= time.Second:
		return d.Round(time.Millisecond)
	case d >= time.Millisecond:
		return d.Round(100 * time.Microsecond)
	default:
		return d.Round(time.Microsecond)
	}
}

// endpointsShown bounds the per-endpoint lines in the report.
const endpointsShown = 5

func describe(r criticalpath.Request) string {
	endpoint := r.Endpoint
	if endpoint == "" {
		endpoint = criticalpath.UnknownEndpoint
	}
	parts := []string{sanitize.Terminal(endpoint)}
	if r.Pod != "" {
		parts = append(parts, sanitize.Terminal(r.Namespace+"/"+r.Pod))
	} else if r.Process != "" {
		parts = append(parts, sanitize.Terminal(r.Process))
	}
	parts = append(parts, "("+r.Kind+")")
	return strings.Join(parts, "  ")
}

func kindCounts(byKind map[string]int) string {
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool {
		if byKind[kinds[i]] != byKind[kinds[j]] {
			return byKind[kinds[i]] > byKind[kinds[j]]
		}
		return kinds[i] < kinds[j]
	})
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d", k, byKind[k]))
	}
	return strings.Join(parts, ", ")
}

func sharesOf(byCategory map[criticalpath.Category]time.Duration) []criticalpath.Share {
	shares := make([]criticalpath.Share, 0, len(byCategory))
	for c, d := range byCategory {
		shares = append(shares, criticalpath.Share{Category: c, Duration: d})
	}
	sort.Slice(shares, func(i, j int) bool {
		if shares[i].Duration != shares[j].Duration {
			return shares[i].Duration > shares[j].Duration
		}
		return shares[i].Category < shares[j].Category
	})
	return shares
}

func formatShares(shares []criticalpath.Share, total time.Duration) string {
	if total <= 0 || len(shares) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(shares))
	for _, s := range shares {
		pct := 100 * float64(s.Duration) / float64(total)
		if pct < 0.05 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %.1f%%", s.Category, pct))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}
