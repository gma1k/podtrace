package diagnose

import (
	"context"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/analysis/criticalpath"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/diagnose/correlator"
	"github.com/gma1k/podtrace/internal/diagnose/export"
	"github.com/gma1k/podtrace/internal/diagnose/profiling"
	"github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/diagnose/stacktrace"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func (d *Diagnostician) ExportJSON() ExportData {
	return export.ExportJSON(d)
}

func (d *Diagnostician) ExportCSV(w io.Writer) error {
	return export.ExportCSV(d, w)
}

type ExportData = export.ExportData

type Diagnostician struct {
	mu                 sync.RWMutex
	events             []*events.Event
	enrichedEvents     []map[string]interface{}
	startTime          time.Time
	endTime            time.Time
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
	maxEvents          int
	eventCount         int
	droppedEvents      int
	seenByType         map[events.EventType]int
	errorsSeen         int
	priorities         []float64
	threshold          float64
	sampling           bool
	sampleUniform      func() float64
	draws              sampleDraws
	sessionSampling    *bufferSampling
	podCommTracker     *tracker.PodCommunicationTracker
	errorCorrelator    *correlator.ErrorCorrelator
	criticalPath       *criticalpath.Collector
	fsKernelRows       []kernelagg.Row
	fsEventTotals      analyzer.FSEventTotals
	fsTotalsInherited  bool
	processCPUNS       map[uint32]uint64
	sourcePod          string
	sourceNamespace    string
	lastSamplingNotice time.Time
	now                func() time.Time
}

func NewDiagnostician() *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		enrichedEvents:     make([]map[string]interface{}, 0),
		startTime:          time.Now(),
		errorRateThreshold: config.DefaultErrorRateThreshold,
		rttSpikeThreshold:  config.DefaultRTTThreshold,
		fsSlowThreshold:    config.DefaultFSSlowThreshold,
		maxEvents:          defaultEventCapacity(),
		errorCorrelator:    correlator.NewErrorCorrelator(30 * time.Second),
		criticalPath:       criticalpath.New(),
	}
}

func NewDiagnosticianWithThresholds(errorRate, rttSpike, fsSlow float64) *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		enrichedEvents:     make([]map[string]interface{}, 0),
		startTime:          time.Now(),
		errorRateThreshold: errorRate,
		rttSpikeThreshold:  rttSpike,
		fsSlowThreshold:    fsSlow,
		maxEvents:          defaultEventCapacity(),
		errorCorrelator:    correlator.NewErrorCorrelator(30 * time.Second),
		criticalPath:       criticalpath.New(),
	}
}

func NewDiagnosticianWithK8s(sourcePod, sourceNamespace string) *Diagnostician {
	d := NewDiagnostician()
	d.sourcePod = sourcePod
	d.sourceNamespace = sourceNamespace
	d.podCommTracker = tracker.NewPodCommunicationTracker(sourcePod, sourceNamespace)
	return d
}

func NewDiagnosticianWithK8sAndThresholds(sourcePod, sourceNamespace string, errorRate, rttSpike, fsSlow float64) *Diagnostician {
	d := NewDiagnosticianWithThresholds(errorRate, rttSpike, fsSlow)
	d.sourcePod = sourcePod
	d.sourceNamespace = sourceNamespace
	d.podCommTracker = tracker.NewPodCommunicationTracker(sourcePod, sourceNamespace)
	return d
}

func (d *Diagnostician) AddEvent(event *events.Event) {
	d.AddEventWithContext(event, nil)
}

func (d *Diagnostician) AddEventWithContext(event *events.Event, k8sContext map[string]interface{}) {
	if event == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.eventCount++
	if d.seenByType == nil {
		d.seenByType = make(map[events.EventType]int)
	}
	d.seenByType[event.Type]++
	if event.IsError() {
		d.errorsSeen++
	}
	if !d.fsTotalsInherited && analyzer.IsFSEvent(event.Type) {
		if d.fsEventTotals == nil {
			d.fsEventTotals = analyzer.FSEventTotals{}
		}
		d.fsEventTotals.Add(event, d.fsSlowThreshold)
	}

	if d.podCommTracker != nil && k8sContext != nil {
		d.podCommTracker.ProcessEvent(event, k8sContext)
	}
	if d.errorCorrelator != nil {
		d.errorCorrelator.AddEvent(event, k8sContext)
	}
	d.criticalPath.Feed(event)

	p := d.priority(event.Type)
	if d.sampling && p >= d.threshold {
		d.droppedEvents++
		d.logSamplingLocked()
		return
	}
	if len(d.events) >= d.maxEvents {
		d.compactLocked()
		d.logSamplingLocked()
		if p >= d.threshold {
			d.droppedEvents++
			return
		}
	}
	d.events = append(d.events, event)
	d.enrichedEvents = append(d.enrichedEvents, k8sContext)
	d.priorities = append(d.priorities, p)
}

// GetEvents returns the buffered events in arrival order.
func (d *Diagnostician) GetEvents() []*events.Event {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]*events.Event(nil), d.events...)
}

// AddFastFilesystemOps keeps the kernel's counts of the filesystem
// operations too fast to become events.
func (d *Diagnostician) AddFastFilesystemOps(rows []kernelagg.Row) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fsKernelRows = append(d.fsKernelRows, rows...)
}

// FilesystemEventTotals returns what every filesystem event this
// diagnostician saw added up to, including those its buffer sampled out.
func (d *Diagnostician) FilesystemEventTotals() analyzer.FSEventTotals {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.fsEventTotals) == 0 {
		return nil
	}
	out := make(analyzer.FSEventTotals, len(d.fsEventTotals))
	for k, v := range d.fsEventTotals {
		out[k] = v
	}
	return out
}

// InheritFilesystemEventTotals makes totals this diagnostician's filesystem
// totals, in place of counting the events it is given, which are a sample.
// Call it before adding events.
func (d *Diagnostician) InheritFilesystemEventTotals(totals analyzer.FSEventTotals) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fsEventTotals = make(analyzer.FSEventTotals, len(totals))
	for k, v := range totals {
		d.fsEventTotals[k] = v
	}
	d.fsTotalsInherited = true
}

// AddProcessCPU keeps the kernel's on-CPU nanoseconds per process ID.
func (d *Diagnostician) AddProcessCPU(times map[uint32]uint64) {
	if len(times) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.processCPUNS == nil {
		d.processCPUNS = make(map[uint32]uint64, len(times))
	}
	for pid, ns := range times {
		d.processCPUNS[pid] += ns
	}
}

// ProcessCPU returns a copy of what AddProcessCPU kept, so a per-pod
// diagnostician can be given it.
func (d *Diagnostician) ProcessCPU() map[uint32]uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.processCPUNS) == 0 {
		return nil
	}
	out := make(map[uint32]uint64, len(d.processCPUNS))
	for pid, ns := range d.processCPUNS {
		out[pid] = ns
	}
	return out
}

// FastFilesystemRows returns the rows AddFastFilesystemOps kept, so a per-pod
// diagnostician can be given them.
func (d *Diagnostician) FastFilesystemRows() []kernelagg.Row {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]kernelagg.Row(nil), d.fsKernelRows...)
}

// FastFilesystemOps sums the kernel's counts for the cgroups this
// diagnostician's events came from, so each pod's report counts its own.
func (d *Diagnostician) FastFilesystemOps() analyzer.FSKernelCounts {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.fsKernelRows) == 0 {
		return nil
	}
	own := make(map[uint64]struct{})
	for _, e := range d.events {
		if e != nil && e.CgroupID != 0 {
			own[e.CgroupID] = struct{}{}
		}
	}
	out := analyzer.FSKernelCounts{}
	for _, r := range d.fsKernelRows {
		if _, ok := own[r.Key.CgroupID]; !ok {
			continue
		}
		typ := events.EventType(r.Key.EventType)
		switch typ {
		case events.EventRead, events.EventWrite, events.EventFsync:
		default:
			continue
		}
		c := out[typ]
		c.Count += r.Value.Count
		c.SumNS += r.Value.SumNS
		c.Bytes += r.Value.Bytes
		if c.Buckets == nil {
			c.Buckets = map[float64]uint64{}
		}
		c.Buckets[kernelBucketUpperMs(r.Key.Bucket)] += r.Value.Count
		out[typ] = c
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// kernelBucketUpperMs is a kernel latency bucket's upper bound in
// milliseconds.
func kernelBucketUpperMs(bucket uint16) float64 {
	return math.Exp2(float64(kernelagg.NativeIndex(bucket))/float64(uint(1)<<kernelagg.Schema)) * 1000
}

// CriticalPath returns where the requests served during collection spent
// their time.
func (d *Diagnostician) CriticalPath() criticalpath.Summary {
	return d.criticalPath.Summary()
}

func (d *Diagnostician) Finish() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.endTime = time.Now()
}

// EventsSeen counts every event added, including those the full buffer
// sampled out.
func (d *Diagnostician) EventsSeen() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.eventCount
}

// EventsSeenByType counts every event added by type, including those the
// full buffer sampled out.
func (d *Diagnostician) EventsSeenByType() map[events.EventType]int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[events.EventType]int, len(d.seenByType))
	for t, n := range d.seenByType {
		out[t] = n
	}
	return out
}

// ErrorsSeen counts every failed event added, including those the full
// buffer sampled out.
func (d *Diagnostician) ErrorsSeen() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.errorsSeen
}

// EventsSampledOut counts the events a full buffer did not keep.
func (d *Diagnostician) EventsSampledOut() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.droppedEvents
}

// bufferSampling is what a full buffer saw and let go.
type bufferSampling struct {
	seen       int
	sampledOut int
}

// InheritSessionSampling records that the events this diagnostician is given
// come from session's buffer, so its report says they are a sample when
// session's buffer sampled.
func (d *Diagnostician) InheritSessionSampling(session *Diagnostician) {
	seen, out := session.EventsSeen(), session.EventsSampledOut()
	if out == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessionSampling = &bufferSampling{seen: seen, sampledOut: out}
}

// SessionSampling returns how many events the session buffer this
// diagnostician's events were taken from saw and sampled out, with ok false
// when they were not taken from a buffer that sampled.
func (d *Diagnostician) SessionSampling() (seen, sampledOut int, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.sessionSampling == nil {
		return 0, 0, false
	}
	return d.sessionSampling.seen, d.sessionSampling.sampledOut, true
}

// EventContexts returns the per-event enrichment contexts, index-aligned with
// GetEvents().
func (d *Diagnostician) EventContexts() []map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return append([]map[string]interface{}(nil), d.enrichedEvents...)
}

// SetTimeWindow overrides the observation window.
func (d *Diagnostician) SetTimeWindow(start, end time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.startTime = start
	d.endTime = end
}

func (d *Diagnostician) CalculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}

// FilterEvents returns the events of a given type.
func (d *Diagnostician) FilterEvents(eventType events.EventType) []*events.Event {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var filtered []*events.Event
	for _, e := range d.events {
		if e != nil && e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (d *Diagnostician) StartTime() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.startTime
}

func (d *Diagnostician) EndTime() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.endTime
}

func (d *Diagnostician) ErrorRateThreshold() float64 {
	return d.errorRateThreshold
}

func (d *Diagnostician) RTTSpikeThreshold() float64 {
	return d.rttSpikeThreshold
}

// SourcePod is the pod this diagnostician diagnoses, "" when not known.
func (d *Diagnostician) SourcePod() string {
	return d.sourcePod
}

// SourceNamespace is the namespace of the pod this diagnostician diagnoses.
func (d *Diagnostician) SourceNamespace() string {
	return d.sourceNamespace
}

func (d *Diagnostician) FSSlowThreshold() float64 {
	return d.fsSlowThreshold
}

func (d *Diagnostician) GenerateReport() string {
	ctx, cancel := context.WithTimeout(context.Background(), config.ReportGenerationTimeout)
	defer cancel()
	return d.GenerateReportWithContext(ctx)
}

// GenerateReportWithContext builds the report section by section, stopping
// when ctx ends: a report cut short says so and keeps what it has.
func (d *Diagnostician) GenerateReportWithContext(ctx context.Context) string {
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return "No events collected during the diagnostic period.\n"
	}

	duration := d.EndTime().Sub(d.StartTime())
	sections := []func() string{
		func() string { return report.GenerateSummarySection(d, duration) },
		func() string { return report.GenerateSecuritySection(d) },
		func() string { return report.GenerateCgroupScopeSection(d) },
		func() string { return report.GenerateDNSSection(d, duration) },
		func() string { return report.GenerateTCPSection(d, duration) },
		func() string { return report.GenerateTLSSection(d, duration) },
		func() string { return report.GenerateConnectionSection(d, duration) },
		func() string { return report.GenerateFileSystemSection(d, duration) },
		func() string { return report.GenerateUDPSection(d, duration) },
		func() string { return report.GenerateHTTPSection(d, duration) },
		func() string { return report.GenerateHTTP3Section(d, duration) },
		func() string { return report.GenerateCPUSection(d, duration) },
		func() string { return report.GenerateTCPStateSection(d, duration) },
		func() string { return report.GenerateMemorySection(d, duration) },
		func() string { return report.GenerateResourceSection(d) },
		func() string { return report.GeneratePoolSection(d, duration) },
		func() string { return profiling.GenerateProcessCPUReport(allEvents, duration, d.ProcessCPU()) },
		func() string { return stacktrace.GenerateStackTraceSectionWithContext(d, ctx) },
		func() string { return report.GenerateSyscallSection(d, duration) },
		func() string { return report.GenerateApplicationTracing(d, duration) },
		func() string { return tracker.GenerateConnectionCorrelation(allEvents) },
		func() string {
			if d.podCommTracker == nil {
				return ""
			}
			return tracker.GeneratePodCommunicationReport(d.podCommTracker.GetSummary())
		},
		func() string {
			if d.errorCorrelator == nil {
				return ""
			}
			return d.errorCorrelator.GetErrorSummary()
		},
		func() string { return report.GenerateIssuesSection(d) },
	}

	return writeSections(ctx, sections)
}

// writeSections joins what each section renders, checking ctx before each.
func writeSections(ctx context.Context, sections []func() string) string {
	var b strings.Builder
	for _, section := range sections {
		if err := ctx.Err(); err != nil {
			if b.Len() == 0 {
				return fmt.Sprintf("Report generation cancelled: %v\n", err)
			}
			fmt.Fprintf(&b, "\nReport generation cancelled: %v; the sections after this point were not generated\n", err)
			break
		}
		b.WriteString(section())
	}
	return b.String()
}
