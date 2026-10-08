package status

import (
	"context"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
)

func TestAnIssueShowsTheAgentsLiveMessageOverItsActivationEvent(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("dns.failure_rate", "shop", "resolver", "", "warning")
	activated := t0.Add(-6 * time.Minute)
	events := []corev1.Event{issueEvent("shop", "resolver-0", "dns.failure_rate", "resolver", "mostly timeout", activated)}
	scrape := AgentScrape{
		Agent: agent("a", "n1"), Window: window(t, m, func() {}), LiveRead: true,
		Live: []LiveIssue{{ID: "dns.failure_rate", Severity: "warning", Namespace: "shop", Workload: "resolver",
			Pod: "resolver-0", Since: activated, Message: "mostly SERVFAIL"}},
	}

	r := Build([]AgentScrape{scrape}, events, Options{}, t0)
	if len(r.Issues) != 1 {
		t.Fatalf("issues = %+v", r.Issues)
	}
	is := r.Issues[0]
	if is.Message != "mostly SERVFAIL" || is.Since == nil || !is.Since.Equal(activated) || is.Pod != "resolver-0" {
		t.Errorf("issue = %+v, want the live message with the activation time", is)
	}
}

func TestAnIssueWhoseEventWasNeverWrittenStillShowsItsDetail(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("dns.slow_lookup_rate", "shop", "resolver", "", "warning")
	scrape := AgentScrape{
		Agent: agent("a", "n1"), Window: window(t, m, func() {}), LiveRead: true,
		Live: []LiveIssue{{ID: "dns.slow_lookup_rate", Severity: "warning", Namespace: "shop", Workload: "resolver",
			Pod: "resolver-0", Since: t0.Add(-time.Minute), Message: "Slow DNS resolution"}},
	}
	r := Build([]AgentScrape{scrape}, nil, Options{}, t0)
	if r.Issues[0].Message != "Slow DNS resolution" || r.Issues[0].Pod != "resolver-0" || r.Issues[0].Since == nil {
		t.Errorf("issue = %+v; with no Event the live view is all there is", r.Issues[0])
	}
}

func TestAnAgentWithoutTheLiveViewFallsBackToTheEvent(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("dns.failure_rate", "shop", "resolver", "", "warning")
	events := []corev1.Event{issueEvent("shop", "resolver-0", "dns.failure_rate", "resolver", "mostly timeout", t0)}
	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, m, func() {})}}, events, Options{}, t0)
	if r.Issues[0].Message != "mostly timeout" {
		t.Errorf("message = %q, want the Event's", r.Issues[0].Message)
	}
}

func TestTheCollectorReadsEachAgentsLiveIssues(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("dns.failure_rate", "shop", "resolver", "", "warning")
	fc := &fakeCluster{
		agents: []Agent{agent("a", "n1")},
		scrape: func(Agent, int) ([]*dto.MetricFamily, error) { return m.families(t), nil },
		live: map[string][]LiveIssue{"a": {{ID: "dns.failure_rate", Severity: "warning", Namespace: "shop",
			Workload: "resolver", Pod: "resolver-0", Since: t0, Message: "live"}}},
	}
	c := &Collector{Cluster: fc, Sleep: func(context.Context, time.Duration) error { return nil }, Now: func() time.Time { return t0 }}
	r, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Issues) != 1 || r.Issues[0].Message != "live" {
		t.Errorf("issues = %+v, want the message the agent serves live", r.Issues)
	}
}

func TestAWorkloadIssueTakesItsPodFromTheEventAndItsMessageFromTheAgent(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("dns.failure_rate", "shop", "resolver", "", "warning")
	activated := t0.Add(-10 * time.Minute)
	events := []corev1.Event{issueEvent("shop", "resolver-0", "dns.failure_rate", "resolver", "mostly timeout", activated)}
	scrape := AgentScrape{
		Agent: agent("a", "n1"), Window: window(t, m, func() {}), LiveRead: true,
		Live: []LiveIssue{{ID: "dns.failure_rate", Severity: "warning", Namespace: "shop", Workload: "resolver",
			Since: activated, Message: "mostly SERVFAIL"}},
	}
	is := Build([]AgentScrape{scrape}, events, Options{}, t0).Issues[0]
	if is.Pod != "resolver-0" || is.Message != "mostly SERVFAIL" {
		t.Errorf("issue = %+v, want the Event's pod and the agent's message", is)
	}
}

func TestAnIssueTheLiveViewDoesNotListFallsBackToItsEvent(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("dns.failure_rate", "shop", "resolver", "", "warning")
	events := []corev1.Event{issueEvent("shop", "resolver-0", "dns.failure_rate", "resolver", "mostly timeout", t0)}
	scrape := AgentScrape{
		Agent: agent("a", "n1"), Window: window(t, m, func() {}), LiveRead: true,
		Live: []LiveIssue{{ID: "dns.slow_lookup_rate", Namespace: "shop", Workload: "resolver", Message: "other issue"}},
	}
	if got := Build([]AgentScrape{scrape}, events, Options{}, t0).Issues[0].Message; got != "mostly timeout" {
		t.Errorf("message = %q, want the Event's when the agent does not list the issue", got)
	}
}
