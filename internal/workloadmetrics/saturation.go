package workloadmetrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

// resourceLabel maps the resource kind the BPF side encodes in TCPState onto a
// stable label value.
func resourceLabel(kind uint32) string {
	switch kind {
	case 0:
		return "cpu"
	case 1:
		return "memory"
	case 2:
		return "io"
	default:
		return "other"
	}
}

// dbSystemLabel maps the name the BPF side writes into the event target onto a
// stable, bounded label value, using OpenTelemetry's db.system vocabulary.
func dbSystemLabel(target string) string {
	switch firstLine(target) {
	case "postgresql-pool":
		return "postgresql"
	case "mysql-pool":
		return "mysql"
	case "sqlite-pool":
		return "sqlite"
	case "default-pool", "":
		return "other"
	default:
		return "other"
	}
}

// newSaturationCollectors builds the saturation families.
func newSaturationCollectors(native bool, withBase func(...string) []string) saturationCollectors {
	return saturationCollectors{
		resourceUtilization: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: metricPrefix + "resource_utilization_percent",
			Help: "Peak utilization of a container's resource limit, 0-100, by resource, held briefly so a healthy replica cannot erase a saturated one. The saturation signal: alert on this before latency degrades rather than after.",
		}, withBase("resource")),

		connectionsOpened: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "db_connections_opened_total",
			Help: "Database connections opened, by db_system. Subtract db_connections_closed_total for connections currently open; a difference that only grows is a connection leak.",
		}, withBase("db_system")),

		connectionsClosed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "db_connections_closed_total",
			Help: "Database connections closed, by db_system. Undercounts when a process exits without closing, so compare rates rather than trusting the absolute difference.",
		}, withBase("db_system")),

		acquireWait: prometheus.NewHistogramVec(
			histogramOpts("db_connection_acquire_seconds",
				"Time callers spent obtaining a pooled database connection, from either cause: "+
					"queueing for a free slot once the pool is at its maximum, or establishing "+
					"a new connection while it is below it. Both are time the caller is blocked "+
					"before its query starts, which is why they share a metric -- but that means "+
					"this is NOT Go's DBStats.WaitCount, which counts only the first. A workload "+
					"churning connections because MaxIdleConns is too low reports here while "+
					"DBStats reports zero waits. Only samples above 1ms are recorded, and only "+
					"Go database/sql is instrumented, so absence means a fast pool or a runtime "+
					"this cannot see. No db_system label: acquisition is upstream of the driver.", native),
			withBase(),
		),
	}
}

// saturationCollectors groups the saturation families so the rest of
// collectors stays readable.
type saturationCollectors struct {
	resourceUtilization *prometheus.GaugeVec

	connectionsOpened *prometheus.CounterVec
	connectionsClosed *prometheus.CounterVec

	acquireWait *prometheus.HistogramVec
}

var utilizationHoldWindow = 6 * config.DefaultResourceMonitorInterval

// utilizationPeak is one series' held maximum.
type utilizationPeak struct {
	value float64
	at    time.Time
}

func (s saturationCollectors) all() []prometheus.Collector {
	return []prometheus.Collector{
		s.resourceUtilization,
		s.connectionsOpened,
		s.connectionsClosed,
	}
}

// histograms are registered separately: when the kernel aggregates, the
// kernelHist collector owns these series and registering the plain vec under
// the same name would leave an empty family shadowing it.
func (s saturationCollectors) histograms() []prometheus.Collector {
	return []prometheus.Collector{s.acquireWait}
}

func (s saturationCollectors) histogramFor(family string) (*prometheus.HistogramVec, bool) {
	if family == "db_connection_acquire_seconds" {
		return s.acquireWait, true
	}
	return nil, false
}

func (s saturationCollectors) counterFor(family string) (*prometheus.CounterVec, bool) {
	switch family {
	case "db_connections_opened_total":
		return s.connectionsOpened, true
	case "db_connections_closed_total":
		return s.connectionsClosed, true
	default:
		return nil, false
	}
}

func (s saturationCollectors) gaugeFor(family string) (*prometheus.GaugeVec, bool) {
	if family == "resource_utilization_percent" {
		return s.resourceUtilization, true
	}
	return nil, false
}

// recordSaturation folds a saturation event into its family, reporting whether
// the event belonged to this plane at all.
func (s *Sink) recordSaturation(e *events.Event, base []string) bool {
	switch e.Type {
	case events.EventResourceLimit:
		if e.Error < 0 {
			return true
		}
		labels := appendLabels(base, resourceLabel(e.TCPState))
		s.setGauge(s.c.sat.resourceUtilization, "resource_utilization_percent",
			labels, s.holdPeak("resource_utilization_percent", labels, float64(e.Error)))
		return true

	default:
		counter, family, ok := s.connectionCounter(e.Type)
		if !ok {
			return false
		}
		s.add(counter, family, appendLabels(base, dbSystemLabel(e.Target)), 1)
		return true
	}
}

// connectionCounter resolves a connection-lifecycle event to the counter that
// records it and the family name that counter is admitted under, reporting
// false for every event type this family does not own.
func (s *Sink) connectionCounter(t events.EventType) (*prometheus.CounterVec, string, bool) {
	switch t {
	case events.EventPoolAcquire:
		return s.c.sat.connectionsOpened, "db_connections_opened_total", true
	case events.EventPoolRelease:
		return s.c.sat.connectionsClosed, "db_connections_closed_total", true
	default:
		return nil, "", false
	}
}

// holdPeak returns the value the gauge should carry: the highest reading seen
// for this series inside utilizationHoldWindow, so a healthy replica reporting
// after a saturated one does not erase it.
func (s *Sink) holdPeak(family string, labelValues []string, value float64) float64 {
	key := peakKey(family, labelValues)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.peaks == nil {
		s.peaks = map[string]utilizationPeak{}
	}
	held, ok := s.peaks[key]
	if !ok || value >= held.value || now.Sub(held.at) > utilizationHoldWindow {
		s.peaks[key] = utilizationPeak{value: value, at: now}
		return value
	}
	return held.value
}

// peakKey identifies a held peak. Shared with the reaper so an evicted series
// and its peak cannot be keyed differently.
func peakKey(family string, labelValues []string) string {
	return family + "\x00" + strings.Join(labelValues, "\x00")
}

// setGauge writes a gauge under the same budget the counters observe. Unlike a
// counter, a gauge that is never written again keeps reporting its last value,
// so the reaper deleting it is what stops a departed workload from looking
// permanently saturated.
func (s *Sink) setGauge(g *prometheus.GaugeVec, family string, labelValues []string, value float64) {
	if !s.admit(family, labelValues) {
		return
	}
	g.WithLabelValues(labelValues...).Set(value)
}
