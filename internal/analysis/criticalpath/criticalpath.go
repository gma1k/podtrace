package criticalpath

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/safeconv"
)

// Segment is one contribution to a request's total latency.
type Segment struct {
	Label     string
	LatencyNS uint64
	Fraction  float64 // filled in when CriticalPath is emitted
}

// CriticalPath is the result of analyzing one completed request window.
type CriticalPath struct {
	PID          uint32
	TotalLatency time.Duration
	Segments     []Segment
}

func (cp CriticalPath) Breakdown(topN int) string {
	if len(cp.Segments) == 0 {
		return ""
	}
	byLabel := make(map[string]float64, len(cp.Segments))
	order := make([]string, 0, len(cp.Segments))
	for _, s := range cp.Segments {
		if _, ok := byLabel[s.Label]; !ok {
			order = append(order, s.Label)
		}
		byLabel[s.Label] += s.Fraction
	}
	sort.SliceStable(order, func(i, j int) bool { return byLabel[order[i]] > byLabel[order[j]] })
	if topN > 0 && len(order) > topN {
		order = order[:topN]
	}
	var b strings.Builder
	for i, label := range order {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %.1f%%", label, byLabel[label]*100)
	}
	return b.String()
}

// requestWindow accumulates segments for a single PID until a boundary event arrives.
type requestWindow struct {
	segments []Segment
	lastSeen time.Time
}

// Analyzer correlates events by PID and emits CriticalPath summaries on
// HTTP / FastCGI / gRPC response boundary events.
type Analyzer struct {
	mu      sync.Mutex
	windows map[uint32]*requestWindow
	timeout time.Duration
	emit    func(CriticalPath)
}

// New creates an Analyzer. emit is called whenever a critical path is finalized.
func New(windowTimeout time.Duration, emit func(CriticalPath)) *Analyzer {
	if windowTimeout <= 0 {
		windowTimeout = 500 * time.Millisecond
	}
	return &Analyzer{
		windows: make(map[uint32]*requestWindow),
		timeout: windowTimeout,
		emit:    emit,
	}
}

// isBoundary returns true for event types that close a request window.
func isBoundary(t events.EventType) bool {
	return t == events.EventHTTPResp || t == events.EventFastCGIResp || t == events.EventGRPCMethod
}

// Feed processes one event. It is safe to call from multiple goroutines.
// The emit callback runs after the analyzer's lock is released, so a slow
// (or re-entrant) callback can neither stall the event hot path nor
// deadlock the analyzer.
func (a *Analyzer) Feed(e *events.Event) {
	if e == nil || e.LatencyNS == 0 {
		return
	}
	a.mu.Lock()

	pid := e.PID
	w, ok := a.windows[pid]
	if !ok {
		w = &requestWindow{}
		a.windows[pid] = w
	}
	w.lastSeen = time.Now()

	var path CriticalPath
	finalized := false
	if isBoundary(e.Type) {
		if len(w.segments) == 0 {
			label := e.TypeString()
			if e.Details != "" {
				label = e.Details
			}
			w.segments = append(w.segments, Segment{Label: label, LatencyNS: e.LatencyNS})
		}
		path, finalized = a.buildPath(pid, w, e.LatencyNS)
		delete(a.windows, pid)
	} else {
		label := e.TypeString()
		if e.Details != "" {
			label = e.Details
		}
		w.segments = append(w.segments, Segment{Label: label, LatencyNS: e.LatencyNS})
	}
	a.mu.Unlock()

	if finalized && a.emit != nil {
		a.emit(path)
	}
}

// Evict removes windows older than the timeout and finalizes them.
// Call periodically to prevent unbounded memory growth. Like Feed, emit
// callbacks run after the lock is released.
func (a *Analyzer) Evict() {
	now := time.Now()
	a.mu.Lock()
	var finalized []CriticalPath
	for pid, w := range a.windows {
		if now.Sub(w.lastSeen) > a.timeout {
			if path, ok := a.buildPath(pid, w, 0); ok {
				finalized = append(finalized, path)
			}
			delete(a.windows, pid)
		}
	}
	a.mu.Unlock()

	if a.emit != nil {
		for _, path := range finalized {
			a.emit(path)
		}
	}
}

// buildPath assembles the CriticalPath for a window. boundaryLatencyNS is
// the request-spanning latency of the boundary event (0 for timeout
// evictions, where the segment sum is the best available total). Callers
// must hold a.mu.
func (a *Analyzer) buildPath(pid uint32, w *requestWindow, boundaryLatencyNS uint64) (CriticalPath, bool) {
	if len(w.segments) == 0 {
		return CriticalPath{}, false
	}
	total := boundaryLatencyNS
	if total == 0 {
		for _, s := range w.segments {
			total += s.LatencyNS
		}
	}
	segs := make([]Segment, len(w.segments))
	copy(segs, w.segments)
	if total > 0 {
		for i := range segs {
			segs[i].Fraction = float64(segs[i].LatencyNS) / float64(total)
		}
	}
	return CriticalPath{
		PID:          pid,
		TotalLatency: time.Duration(safeconv.Uint64ToInt64(total)),
		Segments:     segs,
	}, true
}
