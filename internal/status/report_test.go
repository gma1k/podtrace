package status

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/inspect"
)

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func agent(name, node string) Agent {
	return Agent{Name: name, Node: node, Ready: true, Fleet: "default", Port: 9090}
}

func window(t *testing.T, m *agentMetrics, step func()) inspect.Window {
	t.Helper()
	prev := m.snapshot(t, t0)
	step()
	return inspect.Window{Prev: prev, Cur: m.snapshot(t, t0.Add(10*time.Second))}
}

func issueEvent(ns, pod, id, workload, message string, at time.Time) corev1.Event {
	annotations := map[string]string{alerting.AnnotationAlertSource: alerting.AlertSourceIssue}
	if id != "" {
		annotations[alerting.AnnotationIssueID] = id
		annotations[alerting.AnnotationWorkload] = workload
	}
	return corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: ns, Annotations: annotations},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: pod},
		Reason:         alerting.EventReasonAlert,
		Message:        message,
		FirstTimestamp: metav1.NewTime(at),
		LastTimestamp:  metav1.NewTime(at),
	}
}

func TestEveryAgentStateIsReported(t *testing.T) {
	healthy := newAgentMetrics(false)
	degraded := newAgentMetrics(false)
	degraded.degraded.WithLabelValues("btf_unavailable").Set(1)
	notReady := agent("a-3", "n3")
	notReady.Ready = false
	gr := schema.GroupResource{Resource: "pods"}

	r := Build([]AgentScrape{
		{Agent: agent("a-1", "n1"), Window: window(t, healthy, func() {})},
		{Agent: agent("a-2", "n2"), Window: window(t, degraded, func() {})},
		{Agent: notReady, Window: window(t, newAgentMetrics(false), func() {})},
		{Agent: agent("a-4", "n4"), Err: apierrors.NewForbidden(gr, "a-4", errors.New("no"))},
		{Agent: agent("a-5", "n5"), Err: apierrors.NewServiceUnavailable("no endpoints")},
		{Agent: agent("a-6", "n6"), Err: context.DeadlineExceeded},
		{Agent: agent("a-8", "n8"), Err: errors.New("dial tcp 10.0.0.8:9090: connect: connection refused")},
		{Agent: agent("a-7", "n7"), Err: apierrors.NewTimeoutError("slow", 1)},
	}, nil, Options{}, t0)

	want := map[string][2]string{
		"n1": {StateOK, ""},
		"n2": {StateDegraded, "btf_unavailable"},
		"n3": {StateNotReady, ""},
		"n4": {StateForbidden, "not allowed to read the agent through the API server"},
		"n5": {StateUnreachable, "the API server could not reach the agent"},
		"n6": {StateUnreachable, "timed out"},
		"n8": {StateUnreachable, "dial tcp 10.0.0.8:9090: connect: connection refused"},
		"n7": {StateUnreachable, "timed out"},
	}
	for _, a := range r.Agents {
		if w := want[a.Node]; a.State != w[0] || a.Reason != w[1] {
			t.Errorf("%s: state=%q reason=%q, want %q %q", a.Node, a.State, a.Reason, w[0], w[1])
		}
	}
	if r.Summary.Agents != 8 || r.Summary.AgentsHealthy != 1 {
		t.Errorf("summary = %+v, want 1 of 8 healthy", r.Summary)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "pods/proxy") {
		t.Errorf("warnings %v do not tell a forbidden user which permission is missing", r.Warnings)
	}
}

func TestADegradedAgentWithoutAReasonSaysUnknown(t *testing.T) {
	m := newAgentMetrics(false)
	m.degraded.WithLabelValues("").Set(1)
	r := Build([]AgentScrape{{Agent: agent("a", "n"), Window: window(t, m, func() {})}}, nil, Options{}, t0)
	if r.Agents[0].State != StateDegraded || r.Agents[0].Reason != "unknown" {
		t.Errorf("agent = %+v", r.Agents[0])
	}
}

func TestTheWarningsSayWhatToDo(t *testing.T) {
	none := Build(nil, nil, Options{}, t0)
	none.Assess(nil, nil)
	if p := strings.Join(none.Problems, " "); !strings.Contains(p, "--system-namespace") {
		t.Errorf("no agents: problems = %v, want the hint about --system-namespace", none.Problems)
	}
	all := Build([]AgentScrape{
		{Agent: agent("a", "n1"), Err: errors.New("dial tcp: connection refused")},
		{Agent: agent("b", "n2"), Err: errors.New("dial tcp: connection refused")},
	}, nil, Options{}, t0)
	if !strings.Contains(strings.Join(all.Warnings, " "), "networkPolicy") {
		t.Errorf("every agent unreachable: warnings = %v, want the NetworkPolicy hint", all.Warnings)
	}
	one := Build([]AgentScrape{
		{Agent: agent("a", "n1"), Window: window(t, newAgentMetrics(false), func() {})},
		{Agent: agent("b", "n2"), Err: errors.New("refused")},
	}, nil, Options{}, t0)
	if w := strings.Join(one.Warnings, " "); !strings.Contains(w, "1 of 2 agents") || !strings.Contains(w, "networkPolicy") {
		t.Errorf("one agent unreachable: warnings = %v; on Cilium the agent next to the API server "+
			"stays reachable while the policy blocks the rest, so a partial outage needs the hint too", one.Warnings)
	}
	healthy := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, newAgentMetrics(false), func() {})}}, nil, Options{}, t0)
	if len(healthy.Warnings) != 0 {
		t.Errorf("a healthy fleet has warnings: %v", healthy.Warnings)
	}
}

func TestALongErrorIsCutToOneLine(t *testing.T) {
	_, reason := classifyScrapeError(errors.New("first line\n" + strings.Repeat("x", 300)))
	if strings.Contains(reason, "\n") || len(reason) > 120 {
		t.Errorf("reason = %q", reason)
	}
}

func TestAnIssueIsJoinedToItsEventByIssueAndWorkload(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("l7.error_rate", "shop", "checkout", "", "warning")
	since := t0.Add(-5 * time.Minute)
	events := []corev1.Event{
		issueEvent("shop", "checkout-1", "l7.error_rate", "checkout", "High application error rate", since),
		issueEvent("shop", "checkout-1", "l7.latency_degraded", "checkout", "Slow", t0),
	}

	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, m, func() {})}}, events, Options{}, t0)
	if len(r.Issues) != 1 {
		t.Fatalf("issues = %+v", r.Issues)
	}
	is := r.Issues[0]
	if is.Message != "High application error rate" || is.Since == nil || !is.Since.Equal(since) {
		t.Errorf("issue = %+v; the message and start came from the wrong Event", is)
	}
	if is.Pod != "checkout-1" || is.Node != "n1" {
		t.Errorf("pod=%q node=%q; a workload-level issue should show the pod its Event names", is.Pod, is.Node)
	}
}

func TestAnEventFromAnOlderAgentIsJoinedByPod(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("resource.saturation", "shop", "checkout", "checkout-2", "critical")
	older := issueEvent("shop", "checkout-2", "", "", "Memory at 95%", t0.Add(-time.Minute))
	newer := issueEvent("shop", "checkout-2", "", "", "Memory at 97%", t0)
	newer.LastTimestamp = metav1.Time{}
	newer.EventTime = metav1.NewMicroTime(t0)

	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, m, func() {})}}, []corev1.Event{older, newer}, Options{}, t0)
	if r.Issues[0].Message != "Memory at 97%" {
		t.Errorf("message = %q, want the latest Event for the pod", r.Issues[0].Message)
	}
}

func TestAnIssueWithNoEventStillShows(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("net.rtt_spike_rate", "shop", "checkout", "", "warning")
	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, m, func() {})}}, nil, Options{}, t0)
	if len(r.Issues) != 1 || r.Issues[0].Since != nil || r.Issues[0].Message != "" {
		t.Errorf("issues = %+v", r.Issues)
	}
}

func TestIssuesAreFilteredAndSortedBySeverity(t *testing.T) {
	m := newAgentMetrics(false)
	m.raise("a.info", "shop", "cart", "", "info")
	m.raise("b.critical", "shop", "cart", "", "critical")
	m.raise("c.warning", "shop", "checkout", "", "warning")
	m.raise("d.emergency", "shop", "cart", "", "emergency")
	m.raise("e.unknown", "shop", "cart", "", "")
	m.raise("f.other", "billing", "cart", "", "critical")
	m.issues.WithLabelValues("g.cleared", "shop", "cart", "", "", "warning").Set(0)

	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: window(t, m, func() {})}}, nil,
		Options{Namespace: "shop", Workload: "cart"}, t0)
	var ids []string
	for _, is := range r.Issues {
		ids = append(ids, is.ID)
	}
	if got := strings.Join(ids, ","); got != "d.emergency,b.critical,a.info,e.unknown" {
		t.Errorf("issues = %s", got)
	}
}

func TestWorkloadTrafficAddsUpAcrossNodes(t *testing.T) {
	a, b := newAgentMetrics(false), newAgentMetrics(false)
	wa := window(t, a, func() { a.serve("shop", "checkout", 90, 10, 40*time.Millisecond) })
	wb := window(t, b, func() { b.serve("shop", "checkout", 95, 5, 400*time.Millisecond) })

	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: wa}, {Agent: agent("b", "n2"), Window: wb}}, nil, Options{}, t0)
	if len(r.Workloads) != 1 {
		t.Fatalf("workloads = %+v", r.Workloads)
	}
	w := r.Workloads[0]
	if w.RequestsPerSecond != 20 {
		t.Errorf("req/s = %v, want 20: 200 requests over 10s across two nodes", w.RequestsPerSecond)
	}
	if w.ErrorPercent == nil || *w.ErrorPercent != 7.5 {
		t.Errorf("error %% = %v, want 7.5", value(w.ErrorPercent))
	}
	if w.P95Milliseconds == nil || *w.P95Milliseconds < 100 || *w.P95Milliseconds > 500 {
		t.Errorf("p95 = %v ms; half the requests took 400ms, so p95 is in the 100-500ms bucket", value(w.P95Milliseconds))
	}
	if r.WindowSeconds != 10 {
		t.Errorf("window = %vs", r.WindowSeconds)
	}
}

func TestNativeHistogramsGiveAP95(t *testing.T) {
	m := newAgentMetrics(true)
	w := window(t, m, func() { m.serve("shop", "checkout", 100, 0, 200*time.Millisecond) })
	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: w}}, nil, Options{}, t0)
	p95 := value(r.Workloads[0].P95Milliseconds)
	if r.Workloads[0].P95Milliseconds == nil || p95 < 180 || p95 > 220 {
		t.Errorf("p95 = %v ms, want about 200: the kernel-aggregated histograms are native, and a "+
			"view that only reads classic buckets would show no latency at all", p95)
	}
}

func TestWorkloadsAreRankedFilteredAndCut(t *testing.T) {
	m := newAgentMetrics(false)
	w := window(t, m, func() {
		m.serve("shop", "quiet", 10, 0, time.Millisecond)
		m.serve("shop", "busy", 500, 0, time.Millisecond)
		m.serve("shop", "failing", 10, 5, time.Millisecond)
		m.serve("shop", "same-a", 10, 0, time.Millisecond)
		m.serve("shop", "same-b", 10, 0, time.Millisecond)
		m.serve("billing", "invoices", 1000, 0, time.Millisecond)
		m.requests.WithLabelValues("shop", "", "", "", "http", "2xx", "ok").Add(3)
		m.duration.WithLabelValues("shop", "", "", "", "http").Observe(0.1)
	})
	m.raise("l7.latency_degraded", "shop", "quiet", "", "warning")
	m.raise("resource.saturation", "shop", "no-traffic", "", "critical")
	m.requests.WithLabelValues("shop", "idle", "", "", "http", "2xx", "ok").Add(0)
	cur := m.snapshot(t, t0.Add(10*time.Second))

	r := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: inspect.Window{Prev: w.Prev, Cur: cur}}}, nil, Options{Namespace: "shop"}, t0)
	var got []string
	for _, wl := range r.Workloads {
		got = append(got, wl.Workload)
	}
	if strings.Join(got, ",") != "no-traffic,quiet,failing,busy,same-a,same-b" {
		t.Errorf("order = %v; worst issue first, then issue count, error rate, traffic and name; idle and "+
			"unattributed series left out, billing filtered", got)
	}
	cut := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: w}}, nil, Options{Top: 2}, t0)
	if len(cut.Workloads) != 2 || cut.Workloads[0].Workload != "failing" {
		t.Errorf("top 2 = %+v", cut.Workloads)
	}
	if cut.Summary.Workloads < 6 {
		t.Errorf("summary counts %d workloads; the headline counts all observed, not just the top", cut.Summary.Workloads)
	}
}

func TestAResetOrUnreadyWindowAddsNoTraffic(t *testing.T) {
	m := newAgentMetrics(false)
	m.serve("shop", "checkout", 100, 0, time.Millisecond)
	later := m.snapshot(t, t0.Add(10*time.Second))
	restarted := newAgentMetrics(false)
	restarted.serve("shop", "checkout", 5, 0, time.Millisecond)

	reset := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: inspect.Window{Prev: later, Cur: restarted.snapshot(t, t0.Add(20*time.Second))}}}, nil, Options{}, t0)
	if len(reset.Workloads) != 0 {
		t.Errorf("workloads = %+v; a restarted agent's counters went backwards and have no rate", reset.Workloads)
	}
	first := Build([]AgentScrape{{Agent: agent("a", "n1"), Window: inspect.Window{Cur: later}}}, nil, Options{}, t0)
	if len(first.Workloads) != 0 || first.WindowSeconds != 0 {
		t.Errorf("a window with one read produced rates: %+v", first.Workloads)
	}
}

func TestTheAgentCountsTheWorkloadsItSees(t *testing.T) {
	m := newAgentMetrics(false)
	m.serve("shop", "a", 1, 0, time.Millisecond)
	m.serve("shop", "b", 1, 0, time.Millisecond)
	m.serve("billing", "a", 1, 0, time.Millisecond)
	r := Build([]AgentScrape{{Agent: agent("x", "n1"), Window: window(t, m, func() {})}}, nil, Options{}, t0)
	if r.Agents[0].Workloads != 3 {
		t.Errorf("workloads = %d, want 3", r.Agents[0].Workloads)
	}
}

func TestSummaryReadsAsAHeadline(t *testing.T) {
	got := Summary{Agents: 3, AgentsHealthy: 2, Issues: 1, Workloads: 12}.String()
	if got != "2/3 agents healthy · 1 active issues · 12 workloads observed" {
		t.Errorf("summary = %q", got)
	}
	_ = fmt.Sprint
}
