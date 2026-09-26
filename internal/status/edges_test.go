package status

import (
	"context"
	"errors"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gma1k/podtrace/internal/inspect"
)

func TestTheRealSleepStopsOnAnInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if err := (&Collector{}).sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestAnInterruptBetweenTheTwoReadsStopsTheCollection(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	ctx, cancel := context.WithCancel(context.Background())
	serve := fc.scrape
	fc.scrape = func(a Agent, call int) ([]*dto.MetricFamily, error) {
		if call == 2 {
			cancel()
		}
		return serve(a, call)
	}
	c := &Collector{Cluster: fc, Now: newVirtualTime().Now, Sleep: func(context.Context, time.Duration) error { return nil }}
	if _, err := c.Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the interrupt", err)
	}
}

func TestAnAgentWhoseRefreshWaitIsCutShortIsReportedNotHung(t *testing.T) {
	clock := newVirtualTime()
	fc, _ := servingCluster(t, agent("a", "n1"))
	c := collectorOn(fc, clock)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	c.Window = time.Hour
	c.previous["a"] = scrapeResult{snapshot: c.previous["a"].snapshot, readAt: clock.Now()}
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Agents[0].State != StateUnreachable {
		t.Errorf("state = %q; an agent whose wait was cut short is reported, not hung", r.Agents[0].State)
	}
}

func TestIssuesOfEqualSeverityAreOrderedByName(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("z.last", "shop", "b", "", "warning")
	m.raise("a.first", "shop", "a", "", "warning")
	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, m, func() {})}}, nil, Options{}, t0)
	if r.Issues[0].ID != "a.first" || r.Issues[1].ID != "z.last" {
		t.Errorf("issues = %+v", r.Issues)
	}
}

func TestWorkloadsWithEqualSeverityAreOrderedByIssueCountThenErrors(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("x.one", "shop", "one", "", "warning")
	m.raise("x.one", "shop", "two", "", "warning")
	m.raise("x.two", "shop", "two", "", "warning")
	m.raise("x.one", "shop", "quiet", "", "info")
	w := window(t, m, func() { m.serve("shop", "loud", 10, 5, time.Millisecond) })
	m.raise("x.one", "shop", "loud", "", "info")
	cur := m.snapshot(t, t0.Add(10*time.Second))
	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: inspect.Window{Prev: w.Prev, Cur: cur}}}, nil, Options{}, t0)
	var got []string
	for _, wl := range r.Workloads {
		got = append(got, wl.Workload)
	}
	if len(got) != 4 || got[0] != "two" || got[1] != "one" || got[2] != "loud" || got[3] != "quiet" {
		t.Errorf("order = %v; more issues first, then the higher error rate", got)
	}
}

func TestAnEventWithoutANamespaceOrTimestampsStillJoins(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("l7.error_rate", "shop", "checkout", "", "warning")
	e := issueEvent("shop", "checkout-1", "l7.error_rate", "checkout", "from the Event", time.Time{})
	e.InvolvedObject.Namespace = ""
	e.FirstTimestamp, e.LastTimestamp = metav1.Time{}, metav1.Time{}
	e.CreationTimestamp = metav1.NewTime(t0.Add(-time.Minute))

	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, m, func() {})}}, []corev1.Event{e}, Options{}, t0)
	is := r.Issues[0]
	if is.Message != "from the Event" || is.Since == nil || !is.Since.Equal(t0.Add(-time.Minute)) {
		t.Errorf("issue = %+v; an Event with only its creation time and its own namespace must still join", is)
	}
}
