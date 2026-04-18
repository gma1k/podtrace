package profiling

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
)

// Handler is the event-channel consumer for performance profiling. It:
//   - Watches the event stream for latency spikes and auto-triggers profiling
//   - Accepts on-demand trigger requests via TriggerNow or the HTTP API
//   - Stores the latest CorrelatedResult for report generation
//
// It implements the tracer.ProfilingController interface (HTTPStart, HTTPStatus,
// HTTPResult) so it can be wired into the management port HTTP server.
type Handler struct {
	profiler    *PodProfiler
	mu          sync.RWMutex
	result      *CorrelatedResult
	triggered   atomic.Bool // rate-limit: only one auto-trigger per session
	triggerChan chan triggerReq
	podIP       string
}

type triggerReq struct {
	ptype    ProfileType
	duration time.Duration
}

// NewHandler creates a Handler for the pod at podIP. ports is the list of
// candidate pprof HTTP ports to probe.
func NewHandler(podIP string, ports []int) *Handler {
	return &Handler{
		profiler:    NewPodProfiler(podIP, ports),
		triggerChan: make(chan triggerReq, config.ProfilingMaxConcurrent),
		podIP:       podIP,
	}
}

// Run consumes eventChan, watching for latency spikes that auto-trigger a
// heap + goroutine profile fetch. It also services on-demand trigger requests.
// Run is intended to be called in a goroutine; it exits when ctx is cancelled.
func (h *Handler) Run(ctx context.Context, eventChan <-chan *events.Event) {
	// Try to discover the pprof endpoint once at startup (non-blocking for caller).
	discoverCtx, discoverCancel := context.WithTimeout(ctx, 3*time.Second)
	h.profiler.Discover(discoverCtx)
	discoverCancel()

	for {
		select {
		case <-ctx.Done():
			return
		case req := <-h.triggerChan:
			h.doProfile(ctx, req.ptype, req.duration)
		case e, ok := <-eventChan:
			if !ok {
				return
			}
			h.checkSpike(ctx, e)
		}
	}
}

// checkSpike auto-triggers a heap+goroutine profile when a slow event is seen,
// rate-limited to one trigger per session.
func (h *Handler) checkSpike(ctx context.Context, e *events.Event) {
	if e == nil {
		return
	}
	if !isSlowEventType(e.Type) {
		return
	}
	triggerNS := uint64(config.ProfilingAutoTriggerMS * float64(config.NSPerMS))
	if e.LatencyNS < triggerNS {
		return
	}
	// Only trigger once.
	if !h.triggered.CompareAndSwap(false, true) {
		return
	}
	metricsexporter.RecordProfilingAutoTrigger(h.podIP)
	logger.Info("Profiling auto-triggered by latency spike",
		zap.String("event_type", e.TypeString()),
		zap.Uint64("latency_ns", e.LatencyNS),
		zap.Uint32("pid", e.PID))

	// Run the quick profiles in the background so we don't block the event loop.
	go func() {
		h.doProfile(ctx, ProfileHeap, 0)
		h.doProfile(ctx, ProfileGoroutine, 0)
	}()
}

// doProfile fetches the requested profile type and stores/updates the result.
func (h *Handler) doProfile(ctx context.Context, ptype ProfileType, duration time.Duration) {
	if duration == 0 {
		duration = config.ProfilingDefaultDuration
	}

	var heap, goroutine *ProfileResult

	switch ptype {
	case ProfileHeap:
		heap = h.profiler.FetchHeap(ctx)
		if heap.Error != "" {
			logger.Warn("Heap profile fetch failed", zap.String("error", heap.Error))
			metricsexporter.RecordProfilingFetchError(h.podIP, ProfileHeap.String())
		}
	case ProfileGoroutine:
		goroutine = h.profiler.FetchGoroutine(ctx)
		if goroutine.Error != "" {
			logger.Warn("Goroutine profile fetch failed", zap.String("error", goroutine.Error))
			metricsexporter.RecordProfilingFetchError(h.podIP, ProfileGoroutine.String())
		} else if goroutine.Available {
			metricsexporter.RecordProfilingGoroutines(h.podIP, goroutine.GoroutineCount, goroutine.BlockedCount)
		}
	case ProfileCPU:
		// CPU profile is long; run synchronously (caller already in goroutine).
		cpu := h.profiler.FetchCPUProfile(ctx, duration)
		if cpu.Error != "" {
			logger.Warn("CPU profile fetch failed", zap.String("error", cpu.Error))
			metricsexporter.RecordProfilingFetchError(h.podIP, ProfileCPU.String())
		}
		// CPU profiles don't feed into CorrelatedResult directly — the binary is
		// stored in cpu.RawBytes for potential file export. Update metadata only.
		h.mu.Lock()
		if h.result == nil {
			h.result = &CorrelatedResult{PageFaultCounts: map[uint32]int{}, PodIP: h.podIP}
		}
		h.result.PprofAvailable = cpu.Available
		h.mu.Unlock()
		return
	}

	// Merge new profile data into the stored result.
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.result == nil {
		h.result = &CorrelatedResult{PageFaultCounts: map[uint32]int{}, PodIP: h.podIP}
	}
	if heap != nil {
		h.result.HeapProfile = heap
		if heap.Available {
			h.result.PprofAvailable = true
		}
	}
	if goroutine != nil {
		h.result.GoroutineProfile = goroutine
		if goroutine.Available {
			h.result.PprofAvailable = true
		}
	}
	h.result.PodIP = h.podIP
}

// TriggerNow enqueues an on-demand profile request (non-blocking; drops if full).
func (h *Handler) TriggerNow(ptype ProfileType, duration time.Duration) {
	select {
	case h.triggerChan <- triggerReq{ptype: ptype, duration: duration}:
	default:
		logger.Warn("Profiling trigger channel full; dropping request")
	}
}

// GetResult returns the latest stored CorrelatedResult, or nil if no profiling
// has occurred yet.
func (h *Handler) GetResult() *CorrelatedResult {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.result
}

// GenerateSection correlates allEvents with the stored profiling data and
// returns a formatted report section string.
func (h *Handler) GenerateSection(allEvents []*events.Event, duration time.Duration) string {
	h.mu.RLock()
	storedHeap := h.result
	h.mu.RUnlock()

	var heap, goroutine *ProfileResult
	if storedHeap != nil {
		heap = storedHeap.HeapProfile
		goroutine = storedHeap.GoroutineProfile
	}

	cr := Correlate(allEvents, heap, goroutine, config.ProfilingAutoTriggerMS)
	cr.PodIP = h.podIP

	// Merge pprof availability from profiler discovery.
	if h.profiler.foundPort != 0 {
		cr.PprofAvailable = true
	}

	return GenerateSection(cr, duration)
}

// --- HTTP handlers (implements tracer.ProfilingController) ---

// HTTPStart handles POST /profile/start?type=cpu|heap|goroutine&duration=30s
func (h *Handler) HTTPStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	ptypeStr := q.Get("type")
	if ptypeStr == "" {
		ptypeStr = "heap"
	}
	durationStr := q.Get("duration")
	dur := config.ProfilingDefaultDuration
	if durationStr != "" {
		if d, err := time.ParseDuration(durationStr); err == nil && d > 0 {
			dur = d
		}
	}

	var ptype ProfileType
	switch strings.ToLower(ptypeStr) {
	case "cpu":
		ptype = ProfileCPU
	case "goroutine":
		ptype = ProfileGoroutine
	default:
		ptype = ProfileHeap
	}

	h.TriggerNow(ptype, dur)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":   "triggered",
		"type":     ptype.String(),
		"duration": dur.String(),
	})
}

// HTTPStatus handles GET /profile/status
func (h *Handler) HTTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.RLock()
	hasResult := h.result != nil
	pprofAvail := h.profiler.foundPort != 0
	h.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"pprof_available":  pprofAvail,
		"pprof_port":       h.profiler.foundPort,
		"has_result":       hasResult,
		"auto_triggered":   h.triggered.Load(),
		"trigger_threshold_ms": config.ProfilingAutoTriggerMS,
		"pod_ip":           h.podIP,
	})
}

// HTTPResult handles GET /profile/result
func (h *Handler) HTTPResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.RLock()
	result := h.result
	h.mu.RUnlock()

	if result == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "no_result"})
		return
	}

	// Build a JSON-friendly summary (avoid large raw bytes in the response).
	type frame struct {
		Frame string `json:"frame"`
		Count int    `json:"count"`
	}
	type proc struct {
		PID        uint32  `json:"pid"`
		Name       string  `json:"name"`
		SchedCount int     `json:"sched_count"`
		AvgBlockNS float64 `json:"avg_block_ns"`
	}
	type allocFn struct {
		Function string `json:"function"`
		Bytes    int64  `json:"bytes"`
		Count    int64  `json:"count"`
	}

	hotFrames := make([]frame, len(result.HotFrames))
	for i, f := range result.HotFrames {
		hotFrames[i] = frame(f)
	}
	procs := make([]proc, len(result.CPUHotProcesses))
	for i, p := range result.CPUHotProcesses {
		procs[i] = proc(p)
	}
	var topAllocs []allocFn
	if result.HeapProfile != nil {
		for _, f := range result.HeapProfile.TopFunctions {
			topAllocs = append(topAllocs, allocFn(f))
		}
	}

	goroutineCount := 0
	blockedCount := 0
	if result.GoroutineProfile != nil {
		goroutineCount = result.GoroutineProfile.GoroutineCount
		blockedCount = result.GoroutineProfile.BlockedCount
	}

	pageFaults := map[string]int{}
	for pid, cnt := range result.PageFaultCounts {
		pageFaults[strconv.Itoa(int(pid))] = cnt
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"pprof_available":   result.PprofAvailable,
		"pod_ip":            result.PodIP,
		"slow_event_count":  len(result.SlowEvents),
		"hot_frames":        hotFrames,
		"cpu_hot_processes": procs,
		"top_heap_allocs":   topAllocs,
		"goroutine_count":   goroutineCount,
		"blocked_count":     blockedCount,
		"page_fault_pids":   pageFaults,
		"oom_event_count":   len(result.OOMEvents),
		"start_time":        result.StartTime,
		"end_time":          result.EndTime,
	})
}
