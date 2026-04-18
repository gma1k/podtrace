package profiling

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// FrameCount holds a stack frame address/symbol and how many times it appeared
// in SchedSwitch events during slow-operation windows.
type FrameCount struct {
	Frame string
	Count int
}

// ProcessCPU summarises CPU scheduling activity for a single process.
type ProcessCPU struct {
	PID        uint32
	Name       string
	SchedCount int
	AvgBlockNS float64
}

// CorrelatedResult is the output of Correlate — it ties together BPF-observed
// slow events, CPU hot-path frames from SchedSwitch stacks, memory page-fault
// data, and optional pprof endpoint results fetched from the pod.
type CorrelatedResult struct {
	// Slow events that exceeded the latency trigger threshold.
	SlowEvents []*events.Event

	// CPU hot frames aggregated from EventSchedSwitch events whose time windows
	// overlap with slow events (matched using BPF-to-wall-clock alignment).
	HotFrames []FrameCount

	// All SchedSwitch events aggregated by process.
	CPUHotProcesses []ProcessCPU

	// Memory — BPF-observed page faults and OOM kills.
	PageFaultCounts map[uint32]int   // PID → fault count
	OOMEvents       []*events.Event

	// Optional pprof endpoint data (nil if pod has no pprof server).
	HeapProfile      *ProfileResult
	GoroutineProfile *ProfileResult

	// Whether a pprof endpoint was found on the pod.
	PprofAvailable bool
	PodIP          string

	// Time range covered by the correlation.
	StartTime time.Time
	EndTime   time.Time
}

// Correlate analyses allEvents and the optional profiling results, producing a
// CorrelatedResult that links slow I/O / CPU events with stack-level context.
//
// cpuTriggerMS is the latency threshold in milliseconds above which an event is
// considered "slow" and included in SlowEvents.
func Correlate(
	allEvents []*events.Event,
	heap *ProfileResult,
	goroutine *ProfileResult,
	cpuTriggerMS float64,
) *CorrelatedResult {
	result := &CorrelatedResult{
		PageFaultCounts: map[uint32]int{},
		PprofAvailable:  (heap != nil && heap.Available) || (goroutine != nil && goroutine.Available),
	}
	if heap != nil {
		result.HeapProfile = heap
	}
	if goroutine != nil {
		result.GoroutineProfile = goroutine
	}

	if len(allEvents) == 0 {
		return result
	}

	triggerNS := uint64(cpuTriggerMS * float64(config.NSPerMS))

	// Collect slow events and build time windows around them.
	type window struct{ start, end time.Time }
	var slowWindows []window

	for _, e := range allEvents {
		if e == nil {
			continue
		}
		// Track OOM events regardless of latency.
		if e.Type == events.EventOOMKill {
			result.OOMEvents = append(result.OOMEvents, e)
			continue
		}
		if e.Type == events.EventPageFault {
			result.PageFaultCounts[e.PID]++
			continue
		}

		if e.LatencyNS >= triggerNS && isSlowEventType(e.Type) {
			result.SlowEvents = append(result.SlowEvents, e)
			// Build a ±50ms window around the slow event for SchedSwitch correlation.
			eventWall := BPFTimestampToWall(e.Timestamp)
			slowWindows = append(slowWindows, window{
				start: eventWall.Add(-50 * time.Millisecond),
				end:   eventWall.Add(time.Duration(safeInt64(e.LatencyNS)) + 50*time.Millisecond),
			})
		}
	}

	// Sort slow events by latency (highest first).
	sort.Slice(result.SlowEvents, func(i, j int) bool {
		return result.SlowEvents[i].LatencyNS > result.SlowEvents[j].LatencyNS
	})
	if len(result.SlowEvents) > 20 {
		result.SlowEvents = result.SlowEvents[:20]
	}

	// Aggregate SchedSwitch events: per-process stats + hot frames during slow windows.
	pidStats := map[uint32]*ProcessCPU{}
	frameAgg := map[string]int{}

	for _, e := range allEvents {
		if e == nil || e.Type != events.EventSchedSwitch {
			continue
		}
		ps, ok := pidStats[e.PID]
		if !ok {
			ps = &ProcessCPU{PID: e.PID, Name: e.ProcessName}
			pidStats[e.PID] = ps
		}
		ps.SchedCount++
		ps.AvgBlockNS += float64(e.LatencyNS)

		// Check if this SchedSwitch falls inside any slow-event window.
		if len(slowWindows) > 0 && len(e.Stack) > 0 {
			eventWall := BPFTimestampToWall(e.Timestamp)
			inWindow := false
			for _, w := range slowWindows {
				if !eventWall.Before(w.start) && !eventWall.After(w.end) {
					inWindow = true
					break
				}
			}
			if inWindow {
				// Aggregate the top 3 frames of the stack (skip innermost runtime frames).
				for i, addr := range e.Stack {
					if i >= 3 {
						break
					}
					if addr == 0 {
						continue
					}
					frameKey := fmt.Sprintf("0x%x", addr)
					frameAgg[frameKey]++
				}
			}
		}
	}

	// Finalise per-process averages.
	for _, ps := range pidStats {
		if ps.SchedCount > 0 {
			ps.AvgBlockNS /= float64(ps.SchedCount)
		}
		result.CPUHotProcesses = append(result.CPUHotProcesses, *ps)
	}
	sort.Slice(result.CPUHotProcesses, func(i, j int) bool {
		return result.CPUHotProcesses[i].SchedCount > result.CPUHotProcesses[j].SchedCount
	})
	if len(result.CPUHotProcesses) > 10 {
		result.CPUHotProcesses = result.CPUHotProcesses[:10]
	}

	// Convert frame map to sorted slice.
	for frame, count := range frameAgg {
		result.HotFrames = append(result.HotFrames, FrameCount{Frame: frame, Count: count})
	}
	sort.Slice(result.HotFrames, func(i, j int) bool {
		return result.HotFrames[i].Count > result.HotFrames[j].Count
	})
	if len(result.HotFrames) > 10 {
		result.HotFrames = result.HotFrames[:10]
	}

	if len(allEvents) > 0 {
		result.StartTime = BPFTimestampToWall(allEvents[0].Timestamp)
		result.EndTime = BPFTimestampToWall(allEvents[len(allEvents)-1].Timestamp)
	}

	return result
}

// isSlowEventType returns true for event types where LatencyNS reflects a real
// blocking operation latency worth correlating against CPU profiles.
func isSlowEventType(t events.EventType) bool {
	switch t {
	case events.EventTCPSend, events.EventTCPRecv,
		events.EventConnect,
		events.EventRead, events.EventWrite, events.EventFsync,
		events.EventDNS,
		events.EventDBQuery,
		events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventGRPCMethod,
		events.EventKafkaProduce, events.EventKafkaFetch,
		events.EventTLSHandshake,
		events.EventLockContention,
		events.EventHTTPResp,
		events.EventFastCGIResp:
		return true
	default:
		return false
	}
}

// GenerateSection produces the "Performance Profiling Correlation" report section
// from a CorrelatedResult. It is called by Handler.GenerateSection.
func GenerateSection(cr *CorrelatedResult, duration time.Duration) string {
	if cr == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Performance Profiling Correlation:\n")

	// pprof availability notice.
	if cr.PprofAvailable {
		fmt.Fprintf(&sb, "  pprof endpoint: available (pod %s)\n", cr.PodIP)
	} else {
		sb.WriteString("  pprof endpoint: not found on target pod\n")
		sb.WriteString("    Tip: add  import _ \"net/http/pprof\"  to your Go binary and\n")
		sb.WriteString("    expose a /debug/pprof/ HTTP listener to enable heap / goroutine data.\n")
	}
	sb.WriteString("\n")

	// Slow events summary.
	if len(cr.SlowEvents) > 0 {
		fmt.Fprintf(&sb, "  Slow events (> threshold) count: %d\n", len(cr.SlowEvents))
		sb.WriteString("  Top slow events:\n")
		for i, e := range cr.SlowEvents {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&sb, "    %s  PID=%-6d  %-12s  latency=%v  target=%s\n",
				e.TypeString(),
				e.PID,
				e.ProcessName,
				time.Duration(safeInt64(e.LatencyNS)),
				truncate(e.Target, 60))
		}
		sb.WriteString("\n")
	}

	// CPU hot processes from SchedSwitch.
	if len(cr.CPUHotProcesses) > 0 {
		sb.WriteString("  CPU Scheduling Activity (from BPF sched_switch):\n")
		fmt.Fprintf(&sb, "    %-8s  %-16s  %-10s  %s\n",
			"PID", "Process", "Switches", "Avg Block Time")
		for _, ps := range cr.CPUHotProcesses {
			fmt.Fprintf(&sb, "    %-8d  %-16s  %-10d  %v\n",
				ps.PID, truncate(ps.Name, 15), ps.SchedCount,
				time.Duration(int64(ps.AvgBlockNS)).Round(time.Microsecond))
		}
		sb.WriteString("\n")
	}

	// Hot frames correlated with slow events.
	if len(cr.HotFrames) > 0 {
		sb.WriteString("  CPU hot frames during slow-event windows (BPF stacks):\n")
		for i, f := range cr.HotFrames {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&sb, "    %-5d  %s\n", f.Count, f.Frame)
		}
		sb.WriteString("  (Use addr2line or go tool pprof to resolve addresses to function names)\n\n")
	}

	// Goroutine data.
	if cr.GoroutineProfile != nil && cr.GoroutineProfile.Available {
		fmt.Fprintf(&sb, "  Goroutines: %d total, %d blocked\n",
			cr.GoroutineProfile.GoroutineCount,
			cr.GoroutineProfile.BlockedCount)
		if cr.GoroutineProfile.BlockedCount > 50 {
			sb.WriteString("  WARNING: high blocked goroutine count may indicate lock contention or slow I/O.\n")
		}
		sb.WriteString("\n")
	}

	// Heap data.
	if cr.HeapProfile != nil && cr.HeapProfile.Available && len(cr.HeapProfile.TopFunctions) > 0 {
		sb.WriteString("  Top heap allocating functions (from pprof heap profile):\n")
		for i, f := range cr.HeapProfile.TopFunctions {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&sb, "    %-10s  count=%-6d  %s\n",
				formatBytes(f.Bytes), f.Count, f.Function)
		}
		sb.WriteString("\n")
	}

	// Page faults.
	if len(cr.PageFaultCounts) > 0 {
		type kv struct {
			pid   uint32
			count int
		}
		var faults []kv
		for pid, cnt := range cr.PageFaultCounts {
			faults = append(faults, kv{pid, cnt})
		}
		sort.Slice(faults, func(i, j int) bool { return faults[i].count > faults[j].count })
		fmt.Fprintf(&sb, "  Page faults observed: %d distinct PIDs\n", len(faults))
		for i, f := range faults {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&sb, "    PID %-6d  faults=%d\n", f.pid, f.count)
		}
		sb.WriteString("\n")
	}

	// OOM events.
	if len(cr.OOMEvents) > 0 {
		fmt.Fprintf(&sb, "  OOM Kill events: %d\n", len(cr.OOMEvents))
		for _, e := range cr.OOMEvents {
			fmt.Fprintf(&sb, "    task=%s  mem=%s\n", e.Target, formatBytes(safeInt64(e.Bytes)))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatBytes(b int64) string {
	if b < 0 {
		return "?"
	}
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}
