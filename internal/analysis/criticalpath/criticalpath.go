package criticalpath

import (
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/events"
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
func (a *Analyzer) Feed(e *events.Event) {
	if e == nil || e.LatencyNS == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	pid := e.PID
	w, ok := a.windows[pid]
	if !ok {
		w = &requestWindow{}
		a.windows[pid] = w
	}
	w.lastSeen = time.Now()

	label := e.TypeString()
	if e.Details != "" {
		label = e.Details
	}
	w.segments = append(w.segments, Segment{Label: label, LatencyNS: e.LatencyNS})

	if isBoundary(e.Type) {
		a.finalize(pid, w)
		delete(a.windows, pid)
	}
}

// Evict removes windows older than the timeout and finalizes them.
// Call periodically to prevent unbounded memory growth.
func (a *Analyzer) Evict() {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for pid, w := range a.windows {
		if now.Sub(w.lastSeen) > a.timeout {
			if len(w.segments) > 0 {
				a.finalize(pid, w)
			}
			delete(a.windows, pid)
		}
	}
}

func (a *Analyzer) finalize(pid uint32, w *requestWindow) {
	if len(w.segments) == 0 || a.emit == nil {
		return
	}
	var total uint64
	for _, s := range w.segments {
		total += s.LatencyNS
	}
	segs := make([]Segment, len(w.segments))
	copy(segs, w.segments)
	if total > 0 {
		for i := range segs {
			segs[i].Fraction = float64(segs[i].LatencyNS) / float64(total)
		}
	}
	a.emit(CriticalPath{
		PID:          pid,
		TotalLatency: time.Duration(total),
		Segments:     segs,
	})
}
