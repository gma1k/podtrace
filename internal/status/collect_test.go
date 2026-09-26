package status

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/inspect"
	"github.com/gma1k/podtrace/internal/profiling"
)

type virtualTime struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func newVirtualTime() *virtualTime { return &virtualTime{now: t0} }

func (v *virtualTime) Now() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.now
}

func (v *virtualTime) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.slept = append(v.slept, d)
	v.now = v.now.Add(d)
	return nil
}

func (v *virtualTime) advance(d time.Duration) {
	v.mu.Lock()
	v.now = v.now.Add(d)
	v.mu.Unlock()
}

func (v *virtualTime) sleeps() []time.Duration {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]time.Duration(nil), v.slept...)
}

func collectorOn(fc *fakeCluster, clock *virtualTime) *Collector {
	return &Collector{Cluster: fc, Now: clock.Now, Sleep: clock.Sleep}
}

func servingCluster(t *testing.T, agents ...Agent) (*fakeCluster, map[string]*agentMetrics) {
	t.Helper()
	metrics := map[string]*agentMetrics{}
	for _, a := range agents {
		metrics[a.Name] = newAgentMetrics(false)
	}
	var mu sync.Mutex
	fc := &fakeCluster{agents: agents}
	fc.scrape = func(a Agent, call int) ([]*dto.MetricFamily, error) {
		mu.Lock()
		defer mu.Unlock()
		m := metrics[a.Name]
		m.serve("shop", "checkout", 10*call, 0, 20*time.Millisecond)
		return m.families(t), nil
	}
	return fc, metrics
}

type drainingAgent struct {
	t        *testing.T
	clock    *virtualTime
	rate     float64
	interval time.Duration
	phase    time.Duration

	reg       *prometheus.Registry
	requests  *prometheus.CounterVec
	drainedAt prometheus.Gauge
	since     prometheus.Gauge
	every     prometheus.Gauge
	shown     float64
}

func newDrainingAgent(t *testing.T, clock *virtualTime, rate float64, interval, phase time.Duration) *drainingAgent {
	d := &drainingAgent{t: t, clock: clock, rate: rate, interval: interval, phase: phase, reg: prometheus.NewRegistry()}
	d.requests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyL7Requests, Help: "r"},
		append(append([]string{}, baseLabels...), "protocol", "status_class", "outcome"))
	d.drainedAt = prometheus.NewGauge(prometheus.GaugeOpts{Name: familyDrainedAt, Help: "d"})
	d.since = prometheus.NewGauge(prometheus.GaugeOpts{Name: familySinceDrain, Help: "s"})
	d.every = prometheus.NewGauge(prometheus.GaugeOpts{Name: familyDrainInterval, Help: "i"})
	d.reg.MustRegister(d.requests, d.drainedAt, d.since, d.every)
	return d
}

func (d *drainingAgent) scrape(Agent, int) ([]*dto.MetricFamily, error) {
	now := d.clock.Now()
	elapsed := now.Sub(t0) - d.phase
	last := t0.Add(d.phase + time.Duration(math.Floor(float64(elapsed)/float64(d.interval)))*d.interval)
	truth := d.rate * last.Sub(t0).Seconds()
	if truth > d.shown {
		d.requests.WithLabelValues("shop", "checkout", "Deployment", "app", "http", "2xx", "ok").Add(truth - d.shown)
		d.shown = truth
	}
	d.drainedAt.Set(float64(last.UnixNano()) / 1e9)
	d.since.Set(now.Sub(last).Seconds())
	d.every.Set(d.interval.Seconds())
	f, err := d.reg.Gather()
	if err != nil {
		d.t.Fatal(err)
	}
	return f, nil
}

func agent0() Agent { return agent("a", "n1") }

func TestARateOverAnyWindowIsTheTrueRateWhenCountersMoveOnlyAtADrain(t *testing.T) {
	for _, window := range []time.Duration{3 * time.Second, 10 * time.Second, 15 * time.Second, 25 * time.Second} {
		t.Run(window.String(), func(t *testing.T) {
			clock := newVirtualTime()
			clock.advance(47 * time.Second)
			agent := newDrainingAgent(t, clock, 20, 10*time.Second, 3*time.Second)
			c := collectorOn(&fakeCluster{agents: []Agent{agent0()}, scrape: agent.scrape}, clock)
			c.Window = window

			r, err := c.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Workloads) != 1 || math.Abs(r.Workloads[0].RequestsPerSecond-20) > 0.01 {
				t.Errorf("rate = %+v, want 20/s; the counters move only at a drain, so a rate on the "+
					"reader's clock over %v reads nothing or a multiple of the truth", r.Workloads, window)
			}
			if r.WindowSeconds < window.Seconds() {
				t.Errorf("rates over %vs, shorter than the %v asked for", r.WindowSeconds, window)
			}
		})
	}
}

func TestAStaleDrainIsWaitedOutAndAFreshOneIsNot(t *testing.T) {
	clock := newVirtualTime()
	clock.advance(17 * time.Second)
	agent := newDrainingAgent(t, clock, 20, 10*time.Second, 0)
	c := collectorOn(&fakeCluster{agents: []Agent{agent0()}, scrape: agent.scrape}, clock)
	c.Window = 10 * time.Second
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := clock.sleeps(); len(s) == 0 || s[0] != 3*time.Second+drainSettle {
		t.Errorf("slept %v; the last drain was 7s old, so the first read waits for the next one", s)
	}

	fresh := newVirtualTime()
	fresh.advance(20*time.Second + 200*time.Millisecond)
	agent = newDrainingAgent(t, fresh, 20, 10*time.Second, 0)
	c = collectorOn(&fakeCluster{agents: []Agent{agent0()}, scrape: agent.scrape}, fresh)
	c.Window = 10 * time.Second
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := fresh.sleeps(); len(s) != 1 {
		t.Errorf("slept %v; a drain 200ms old is fresh, so only the window is waited", s)
	}
}

func TestARefreshBeforeTheNextDrainWaitsForIt(t *testing.T) {
	clock := newVirtualTime()
	clock.advance(20*time.Second + 100*time.Millisecond)
	agent := newDrainingAgent(t, clock, 20, 10*time.Second, 0)
	c := collectorOn(&fakeCluster{agents: []Agent{agent0()}, scrape: agent.scrape}, clock)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.advance(2 * time.Second)
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Workloads) != 1 || math.Abs(r.Workloads[0].RequestsPerSecond-20) > 0.01 {
		t.Errorf("refresh rate = %+v, want 20/s rather than a window with no drain in it", r.Workloads)
	}
}

func TestAReadWithoutADrainClockUsesTheReadersClock(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	c := collectorOn(fc, newVirtualTime())
	c.Window = 7 * time.Second

	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fc.scrapeCount("a") != 2 {
		t.Errorf("scrapes = %d, want two: one, a wait of the window, and one more", fc.scrapeCount("a"))
	}
	if r.WindowSeconds != 7 || len(r.Workloads) != 1 || r.Workloads[0].RequestsPerSecond <= 0 {
		t.Errorf("window=%v workloads=%+v", r.WindowSeconds, r.Workloads)
	}
}

func TestARefreshCostsOneRead(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	clock := newVirtualTime()
	c := collectorOn(fc, clock)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.advance(10 * time.Second)
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fc.scrapeCount("a") != 3 || len(r.Workloads) != 1 {
		t.Errorf("scrapes=%d workloads=%+v; a --watch refresh must reuse the last read", fc.scrapeCount("a"), r.Workloads)
	}
}

func TestAClockThatNeverMovesIsReadAFewTimesAtMost(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	c := &Collector{Cluster: fc, Sleep: noSleep, Now: func() time.Time { return t0 }, Window: time.Minute}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fc.scrapeCount("a"); got > 1+maxReadAttempts {
		t.Errorf("%d scrapes; a read that never satisfies the window must not repeat forever", got)
	}
}

func TestOneFailingAgentDoesNotHideTheOthers(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"), agent("b", "n2"))
	serve := fc.scrape
	fc.scrape = func(a Agent, call int) ([]*dto.MetricFamily, error) {
		if a.Name == "b" {
			return nil, errors.New("connection refused")
		}
		return serve(a, call)
	}
	r, err := collectorOn(fc, newVirtualTime()).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Agents[0].State != StateOK || r.Agents[1].State != StateUnreachable || len(r.Workloads) != 1 {
		t.Errorf("agents = %+v workloads = %+v", r.Agents, r.Workloads)
	}
}

func TestAnAgentThatComesBackMidWatchGetsRatesNextTime(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	serve := fc.scrape
	down := true
	fc.scrape = func(a Agent, call int) ([]*dto.MetricFamily, error) {
		if down {
			return nil, errors.New("refused")
		}
		return serve(a, call)
	}
	clock := newVirtualTime()
	c := collectorOn(fc, clock)
	_, _ = c.Collect(context.Background())
	down = false
	clock.advance(10 * time.Second)
	back, _ := c.Collect(context.Background())
	if back.Agents[0].State != StateOK || len(back.Workloads) != 0 {
		t.Errorf("first read after recovery: agents=%+v workloads=%+v; with one read there is no rate yet", back.Agents, back.Workloads)
	}
	clock.advance(10 * time.Second)
	next, _ := c.Collect(context.Background())
	if len(next.Workloads) != 1 {
		t.Errorf("the next refresh still has no rates: %+v", next.Workloads)
	}
}

func TestListingTheAgentsFailingIsFatal(t *testing.T) {
	fc := &fakeCluster{agentsErr: errors.New("forbidden")}
	c := collectorOn(fc, newVirtualTime())
	if _, err := c.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "list podtrace agents") {
		t.Errorf("err = %v", err)
	}
	if _, _, err := c.Profile(context.Background(), "shop", "checkout", 5); err == nil {
		t.Error("the profile path ignored the listing error")
	}
}

func TestAnInterruptStopsTheCollection(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Collector{Cluster: fc, Window: time.Hour}).Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the interrupt", err)
	}

	clock := newVirtualTime()
	clock.advance(5 * time.Second)
	agent := newDrainingAgent(t, clock, 1, 10*time.Second, 0)
	ctx, cancel = context.WithCancel(context.Background())
	c := &Collector{Cluster: &fakeCluster{agents: []Agent{agent0()}, scrape: agent.scrape}, Now: clock.Now,
		Sleep: func(context.Context, time.Duration) error { cancel(); return context.Canceled }}
	if _, err := c.Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("an interrupt while waiting for a drain: err = %v", err)
	}
}

func TestTheRealClockAndSleepAreUsedByDefault(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	c := &Collector{Cluster: fc, Window: 20 * time.Millisecond}
	start := time.Now()
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 20*time.Millisecond || r.GeneratedAt.Before(start) {
		t.Errorf("did not wait the window or stamp the report with the real clock")
	}
}

func TestUnreadableIssueEventsAreAWarningNotAFailure(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	fc.eventsErr = errors.New("events is forbidden")
	r, err := collectorOn(fc, newVirtualTime()).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "issue Events") {
		t.Errorf("warnings = %v", r.Warnings)
	}
}

func TestRequestsAreBounded(t *testing.T) {
	var agents []Agent
	for i := 0; i < 12; i++ {
		agents = append(agents, agent(fmt.Sprintf("a-%d", i), fmt.Sprintf("n%d", i)))
	}
	fc, _ := servingCluster(t, agents...)
	fc.gate = make(chan struct{})
	done := make(chan struct{})
	go func() {
		c := collectorOn(fc, newVirtualTime())
		c.Concurrency = 4
		_, _ = c.Collect(context.Background())
		close(done)
	}()
	for open := true; open; {
		select {
		case fc.gate <- struct{}{}:
		case <-done:
			open = false
		}
	}
	if got := fc.maxInFlight.Load(); got < 2 || got > 4 {
		t.Errorf("%d scrapes ran at once, want between 2 and the limit of 4", got)
	}
}

func TestTheProfileIsMergedAcrossNodesAndFailuresAreNamed(t *testing.T) {
	fc := &fakeCluster{
		agents: []Agent{agent("a", "n1"), agent("b", "n2"), agent("c", "n3")},
		profiles: map[string]Profile{
			"a": {Profiles: []profiling.WorkloadProfile{{Namespace: "shop", Workload: "checkout", Samples: 100,
				Frames: []profiling.FrameCount{{Frame: "main.price", Count: 60}}}}},
			"b": {Profiles: []profiling.WorkloadProfile{{Namespace: "shop", Workload: "checkout", Samples: 100,
				Frames: []profiling.FrameCount{{Frame: "main.price", Count: 20}, {Frame: "json.Marshal", Count: 30}}}}},
		},
		profErr: map[string]error{"c": errors.New("timeout")},
	}
	hot, failed, err := (&Collector{Cluster: fc}).Profile(context.Background(), "shop", "checkout", 5)
	if err != nil {
		t.Fatal(err)
	}
	if hot == nil || hot.Samples != 200 || hot.Nodes != 2 || hot.Frames[0].Frame != "main.price" || hot.Frames[0].Percent != 40 {
		t.Errorf("profile = %+v", hot)
	}
	if len(failed) != 1 || !strings.Contains(failed[0], "n3") {
		t.Errorf("failures = %v, want the node that gave no profile", failed)
	}
}

func TestADrainClockNeedsAllThreeGauges(t *testing.T) {
	for name, set := range map[string]func(*drainingAgent){
		"no timestamp":  func(d *drainingAgent) { d.reg.Unregister(d.drainedAt) },
		"never drained": func(d *drainingAgent) { d.drainedAt.Set(0) },
		"no age":        func(d *drainingAgent) { d.reg.Unregister(d.since) },
		"negative age":  func(d *drainingAgent) { d.since.Set(-1) },
		"no interval":   func(d *drainingAgent) { d.reg.Unregister(d.every) },
		"zero interval": func(d *drainingAgent) { d.every.Set(0) },
	} {
		t.Run(name, func(t *testing.T) {
			d := newDrainingAgent(t, newVirtualTime(), 1, 10*time.Second, 0)
			d.drainedAt.Set(float64(t0.Unix()))
			d.since.Set(1)
			d.every.Set(10)
			set(d)
			f, _ := d.reg.Gather()
			if _, ok := drainClockOf(inspect.TakeFamilies(f, t0)); ok {
				t.Error("an incomplete drain clock was trusted")
			}
		})
	}
}

func TestADrainAHairEarlyStillEndsTheWindow(t *testing.T) {
	interval := 10 * time.Second
	previous := inspect.TakeFamilies(nil, t0)
	early := drainGauges(t, t0.Add(interval-200*time.Microsecond), 100*time.Millisecond, interval)
	want := readAfter{previous: previous, previousReadAt: t0, window: interval}
	if d := want.wait(early, t0.Add(interval)); d != 0 {
		t.Errorf("waited %v for a drain 0.2ms early; the ticker jitters, and waiting a whole "+
			"interval for it doubles the first report's time", d)
	}
	late := drainGauges(t, t0.Add(interval/2), 100*time.Millisecond, interval)
	if d := want.wait(late, t0.Add(interval/2)); d <= 0 {
		t.Error("a drain half a window in was taken as the end of the window")
	}
}

func drainGauges(t *testing.T, at time.Time, since, interval time.Duration) inspect.Snapshot {
	t.Helper()
	d := newDrainingAgent(t, newVirtualTime(), 0, interval, 0)
	d.drainedAt.Set(float64(at.UnixNano()) / 1e9)
	d.since.Set(since.Seconds())
	d.every.Set(interval.Seconds())
	f, err := d.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	return inspect.TakeFamilies(f, at)
}
