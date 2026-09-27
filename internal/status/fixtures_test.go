package status

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"

	"github.com/gma1k/podtrace/internal/inspect"
	"github.com/gma1k/podtrace/internal/profiling"
)

var baseLabels = []string{"namespace", "workload", "workload_kind", "container"}

type agentMetrics struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	issues   *prometheus.GaugeVec
	degraded *prometheus.GaugeVec
}

func newAgentMetrics(native bool) *agentMetrics {
	opts := prometheus.HistogramOpts{Name: familyL7Duration, Help: "d"}
	if native {
		opts.NativeHistogramBucketFactor = 1.1
	} else {
		opts.Buckets = []float64{0.01, 0.05, 0.1, 0.5, 1}
	}
	m := &agentMetrics{
		reg:      prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyL7Requests, Help: "r"}, append(append([]string{}, baseLabels...), "protocol", "status_class", "outcome")),
		duration: prometheus.NewHistogramVec(opts, append(append([]string{}, baseLabels...), "protocol")),
		issues:   prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: familyIssueActive, Help: "i"}, []string{"id", "namespace", "workload", "pod", "resource", "severity"}),
		degraded: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: familyDegraded, Help: "g"}, []string{"reason"}),
	}
	m.reg.MustRegister(m.requests, m.duration, m.issues, m.degraded)
	return m
}

func (m *agentMetrics) serve(ns, wl string, ok, failed int, latency time.Duration) {
	m.requests.WithLabelValues(ns, wl, "Deployment", "app", "http", "2xx", "ok").Add(float64(ok))
	if failed > 0 {
		m.requests.WithLabelValues(ns, wl, "Deployment", "app", "http", "5xx", "error").Add(float64(failed))
	}
	for i := 0; i < ok+failed; i++ {
		m.duration.WithLabelValues(ns, wl, "Deployment", "app", "http").Observe(latency.Seconds())
	}
}

func (m *agentMetrics) raise(id, ns, wl, pod, severity string) {
	m.issues.WithLabelValues(id, ns, wl, pod, "", severity).Set(1)
}

func (m *agentMetrics) families(t *testing.T) []*dto.MetricFamily {
	t.Helper()
	f, err := m.reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	return f
}

func (m *agentMetrics) snapshot(t *testing.T, at time.Time) inspect.Snapshot {
	t.Helper()
	s, err := inspect.Take(m.reg, at)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	return s
}

type fakeCluster struct {
	mu        sync.Mutex
	agents    []Agent
	agentsErr error
	scrape    func(agent Agent, call int) ([]*dto.MetricFamily, error)
	profiles  map[string]Profile
	profErr   map[string]error
	stacks    map[string][]byte
	stackErr  map[string]error
	events    []corev1.Event
	eventsErr error

	components    []Component
	componentsErr error

	scrapes     map[string]int
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	gate        chan struct{}
}

func (f *fakeCluster) Agents(context.Context) ([]Agent, error) { return f.agents, f.agentsErr }

func (f *fakeCluster) Scrape(_ context.Context, a Agent) ([]*dto.MetricFamily, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		m := f.maxInFlight.Load()
		if n <= m || f.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	if f.scrapes == nil {
		f.scrapes = map[string]int{}
	}
	f.scrapes[a.Name]++
	call := f.scrapes[a.Name]
	f.mu.Unlock()
	return f.scrape(a, call)
}

func (f *fakeCluster) Profile(_ context.Context, a Agent) (Profile, error) {
	if err := f.profErr[a.Name]; err != nil {
		return Profile{}, err
	}
	return f.profiles[a.Name], nil
}

func (f *fakeCluster) ProfileStacks(_ context.Context, a Agent, _ StackFormat, _ profiling.StackSelection) ([]byte, error) {
	if err := f.stackErr[a.Name]; err != nil {
		return nil, err
	}
	return f.stacks[a.Name], nil
}

func (f *fakeCluster) IssueEvents(context.Context, string) ([]corev1.Event, error) {
	return f.events, f.eventsErr
}

func (f *fakeCluster) Components(context.Context) ([]Component, error) {
	return f.components, f.componentsErr
}

func (f *fakeCluster) scrapeCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scrapes[name]
}

func noSleep(context.Context, time.Duration) error { return nil }
