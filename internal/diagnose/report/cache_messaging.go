package report

import (
	"fmt"
	"sort"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/sanitize"
	"github.com/gma1k/podtrace/internal/spanattributes"
)

// operationStat aggregates the calls that share one operation name.
type operationStat struct {
	name      string
	count     int
	errors    int
	bytes     uint64
	latencies []uint64
}

func (s *operationStat) add(e *events.Event) {
	s.count++
	if e.IsError() {
		s.errors++
	}
	s.bytes += e.Bytes
	s.latencies = append(s.latencies, e.LatencyNS)
}

// groupOperations groups events by the key name returns, most frequent
// first.
func groupOperations(evs []*events.Event, name func(*events.Event) string) []*operationStat {
	byName := map[string]*operationStat{}
	for _, e := range evs {
		if e == nil {
			continue
		}
		key := name(e)
		s, ok := byName[key]
		if !ok {
			s = &operationStat{name: key}
			byName[key] = s
		}
		s.add(e)
	}
	stats := make([]*operationStat, 0, len(byName))
	for _, s := range byName {
		sort.Slice(s.latencies, func(i, j int) bool { return s.latencies[i] < s.latencies[j] })
		stats = append(stats, s)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count != stats[j].count {
			return stats[i].count > stats[j].count
		}
		return stats[i].name < stats[j].name
	})
	return stats
}

// operationLine renders one operation. The name is never followed by a colon:
// the report is redacted as text, and "AUTH: 16" or a topic called "token"
// would read as a credential key and lose its count.
func operationLine(s *operationStat, unit string, withBytes bool) string {
	line := fmt.Sprintf("    - %s (%d %s", sanitize.Terminal(s.name), s.count, unit)
	if withBytes && s.bytes > 0 {
		line += ", " + analyzer.FormatBytes(s.bytes)
	}
	line += ")"
	if len(s.latencies) > 0 {
		line += fmt.Sprintf(", p50=%.2fms, p95=%.2fms, p99=%.2fms, max=%.2fms",
			percentileMs(s.latencies, 50), percentileMs(s.latencies, 95),
			percentileMs(s.latencies, 99), percentileMs(s.latencies, 100))
	}
	if s.errors > 0 {
		line += fmt.Sprintf(", errors=%d", s.errors)
	}
	return line + "\n"
}

func countErrors(evs []*events.Event) int {
	n := 0
	for _, e := range evs {
		if e != nil && e.IsError() {
			n++
		}
	}
	return n
}

func operationOrUnknown(e *events.Event) string {
	if op := spanattributes.Token(e.Details); op != "" {
		return op
	}
	return "unknown"
}

// formatCommandActivity renders a key-value store's commands by name.
func formatCommandActivity(d Diagnostician, duration time.Duration, title string, eventType events.EventType) string {
	cmds := d.FilterEvents(eventType)
	if len(cmds) == 0 {
		return ""
	}
	result := title + " Activity:\n"
	result += fmt.Sprintf("  Commands: %d (%.1f/sec)\n", len(cmds), d.CalculateRate(len(cmds), duration))
	if errs := countErrors(cmds); errs > 0 {
		result += fmt.Sprintf("  Failed:   %d (%.1f%%)\n", errs, 100*float64(errs)/float64(len(cmds)))
	}
	result += "  Top commands:\n"
	for i, s := range groupOperations(cmds, operationOrUnknown) {
		if i >= config.TopProcessesLimit {
			break
		}
		result += operationLine(s, "calls", false)
	}
	return result + "\n"
}

// formatKafkaActivity renders produced and consumed messages by topic.
func formatKafkaActivity(d Diagnostician, duration time.Duration) string {
	produced := d.FilterEvents(events.EventKafkaProduce)
	fetched := d.FilterEvents(events.EventKafkaFetch)
	if len(produced) == 0 && len(fetched) == 0 {
		return ""
	}
	result := "Kafka Activity:\n"
	for _, part := range []struct {
		label, direction string
		evs              []*events.Event
	}{{"Produced", "produce", produced}, {"Consumed", "consume", fetched}} {
		if len(part.evs) == 0 {
			continue
		}
		result += fmt.Sprintf("  %s: %d messages (%.1f/sec)", part.label, len(part.evs), d.CalculateRate(len(part.evs), duration))
		if errs := countErrors(part.evs); errs > 0 {
			result += fmt.Sprintf(", %d failed", errs)
		}
		result += "\n"
		result += "  Top topics (" + part.direction + "):\n"
		for i, s := range groupOperations(part.evs, operationOrUnknown) {
			if i >= config.TopProcessesLimit {
				break
			}
			result += operationLine(s, "messages", true)
		}
	}
	return result + "\n"
}
