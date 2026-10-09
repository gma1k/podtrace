package status

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/inspect"
)

const (
	familyL7Requests  = "podtrace_workload_l7_requests_total"
	familyL7Duration  = "podtrace_workload_l7_request_duration_seconds"
	familyIssueActive = "podtrace_issue_active"
	familyDegraded    = "podtrace_agent_backend_degraded"
)

// Agent states.
const (
	StateOK          = "ok"
	StateDegraded    = "degraded"
	StateNotReady    = "not ready"
	StateUnreachable = "unreachable"
	StateForbidden   = "forbidden"
)

// Report is everything `podtrace status` shows.
type Report struct {
	GeneratedAt   time.Time          `json:"generatedAt"`
	WindowSeconds float64            `json:"windowSeconds"`
	Healthy       bool               `json:"healthy"`
	Problems      []string           `json:"problems,omitempty"`
	Components    []ComponentStatus  `json:"components"`
	Summary       Summary            `json:"summary"`
	Agents        []AgentStatus      `json:"agents"`
	Issues        []Issue            `json:"issues"`
	Workloads     []Workload         `json:"workloads"`
	Profile       *WorkloadHotFrames `json:"profile,omitempty"`
	Warnings      []string           `json:"warnings,omitempty"`
}

// ComponentStatus is how far the operator or one fleet is rolled out.
type ComponentStatus struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Fleet   string `json:"fleet,omitempty"`
	Desired int32  `json:"desired"`
	Ready   int32  `json:"ready"`
	Updated int32  `json:"updated"`
	State   string `json:"state"`
}

// Summary is the one-line headline.
type Summary struct {
	Agents        int `json:"agents"`
	AgentsHealthy int `json:"agentsHealthy"`
	Issues        int `json:"issues"`
	Workloads     int `json:"workloads"`
}

// AgentStatus is one node's agent.
type AgentStatus struct {
	Node      string `json:"node"`
	Pod       string `json:"pod"`
	Fleet     string `json:"fleet,omitempty"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	Restarts  int32  `json:"restarts"`
	Workloads int    `json:"workloads"`
}

// Issue is one active issue.
type Issue struct {
	ID        string     `json:"id"`
	Severity  string     `json:"severity"`
	Namespace string     `json:"namespace"`
	Workload  string     `json:"workload"`
	Pod       string     `json:"pod,omitempty"`
	Resource  string     `json:"resource,omitempty"`
	Node      string     `json:"node"`
	Since     *time.Time `json:"since,omitempty"`
	Message   string     `json:"message,omitempty"`

	Causes []detector.Cause `json:"causes,omitempty"`
}

// Workload is one workload's traffic over the window.
type Workload struct {
	Namespace         string   `json:"namespace"`
	Workload          string   `json:"workload"`
	RequestsPerSecond float64  `json:"requestsPerSecond"`
	ErrorPercent      *float64 `json:"errorPercent,omitempty"`
	P95Milliseconds   *float64 `json:"p95Milliseconds,omitempty"`
	Issues            int      `json:"issues"`
}

// Options narrow and size the report.
type Options struct {
	Namespace string
	Workload  string
	Top       int
}

func (o Options) matches(namespace, workload string) bool {
	return (o.Namespace == "" || o.Namespace == namespace) && (o.Workload == "" || o.Workload == workload)
}

// AgentScrape is what was read from one agent: two gathers a window apart,
// or the error that stopped it.
type AgentScrape struct {
	Agent  Agent
	Window inspect.Window
	Err    error

	Live     []LiveIssue
	LiveRead bool
}

// Build turns the scrapes into a report. It does no I/O.
func Build(scrapes []AgentScrape, events []corev1.Event, opts Options, now time.Time) Report {
	r := Report{
		GeneratedAt: now,
		Components:  []ComponentStatus{},
		Agents:      []AgentStatus{},
		Issues:      []Issue{},
		Workloads:   []Workload{},
	}
	latest := indexIssueEvents(events)
	workloads := map[string]*workloadTotals{}
	var forbidden, unreachable int

	for _, s := range scrapes {
		st := AgentStatus{Node: s.Agent.Node, Pod: s.Agent.Name, Fleet: s.Agent.Fleet, Restarts: s.Agent.Restarts}
		switch {
		case s.Err != nil && s.Agent.Ready:
			st.State, st.Reason = classifyScrapeError(s.Err)
			if st.State == StateForbidden {
				forbidden++
			} else {
				unreachable++
			}
		case !s.Agent.Ready:
			st.State = StateNotReady
		default:
			st.State = StateOK
		}
		if s.Err == nil {
			if reason := degradedReason(s.Window.Cur); reason != "" {
				st.State, st.Reason = StateDegraded, reason
			}
			st.Workloads = countWorkloads(s.Window.Cur)
			r.Issues = append(r.Issues, issuesOf(s, latest, opts)...)
			addTraffic(workloads, s.Window, opts)
			if w := s.Window.Interval().Seconds(); w > r.WindowSeconds {
				r.WindowSeconds = w
			}
		}
		if st.State == StateOK {
			r.Summary.AgentsHealthy++
		}
		r.Agents = append(r.Agents, st)
	}

	for _, is := range r.Issues {
		t, ok := workloads[is.Namespace+"/"+is.Workload]
		if !ok {
			t = &workloadTotals{namespace: is.Namespace, workload: is.Workload}
			workloads[is.Namespace+"/"+is.Workload] = t
		}
		t.issues++
		if rank := severityRank(is.Severity); rank > t.worst {
			t.worst = rank
		}
	}
	r.Workloads = rankWorkloads(workloads, opts.Top)

	sort.Slice(r.Agents, func(i, j int) bool { return r.Agents[i].Node < r.Agents[j].Node })
	sort.Slice(r.Issues, func(i, j int) bool {
		a, b := r.Issues[i], r.Issues[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		return a.Namespace+"/"+a.Workload+"/"+a.ID < b.Namespace+"/"+b.Workload+"/"+b.ID
	})

	r.Summary.Agents = len(r.Agents)
	r.Summary.Issues = len(r.Issues)
	r.Summary.Workloads = len(workloads)
	r.Warnings = warnings(len(scrapes), forbidden, unreachable)
	return r
}

// AttachCauses replaces each issue's causes with the operator's cluster-wide
// view, which also sees causes on the workloads an issue's workload calls.
// An issue the operator has not yet seen keeps the causes its own agent found.
func (r *Report) AttachCauses(c Correlation) {
	byIssue := make(map[detector.IssueRef][]detector.Cause, len(c.Issues))
	for _, is := range c.Issues {
		byIssue[is.IssueRef] = is.Causes
	}
	for i := range r.Issues {
		is := &r.Issues[i]
		ref := detector.IssueRef{ID: detector.ID(is.ID), Namespace: is.Namespace, Workload: is.Workload}
		if causes, ok := byIssue[ref]; ok {
			is.Causes = causes
		}
	}
}

func classifyScrapeError(err error) (state, reason string) {
	if apierrors.IsForbidden(err) {
		return StateForbidden, "not allowed to read the agent through the API server"
	}
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout(), apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
		return StateUnreachable, "timed out"
	case apierrors.IsServiceUnavailable(err), apierrors.IsInternalError(err):
		return StateUnreachable, "the API server could not reach the agent"
	}
	return StateUnreachable, oneLine(err.Error())
}

func oneLine(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

func warnings(total, forbidden, unreachable int) []string {
	var out []string
	if forbidden > 0 {
		out = append(out, "your user may not read the agents: podtrace status needs get on "+
			"pods/proxy in the podtrace system namespace")
	}
	if unreachable > 0 {
		out = append(out, fmt.Sprintf("%d of %d agents could not be reached through the API server; "+
			"if the chart's networkPolicy is enabled with metricsFrom, the API server needs to be "+
			"allowed to the agents' metrics port: on Cilium set networkPolicy.allowAPIServerProxy, "+
			"elsewhere add the control-plane node addresses to networkPolicy.metricsFrom", unreachable, total))
	}
	return out
}

func degradedReason(s inspect.Snapshot) string {
	for _, sample := range s.Family(familyDegraded) {
		if sample.Value > 0 {
			if r := sample.Label("reason"); r != "" {
				return r
			}
			return "unknown"
		}
	}
	return ""
}

func countWorkloads(s inspect.Snapshot) int {
	seen := map[string]struct{}{}
	for _, name := range []string{familyL7Requests, familyL7Duration} {
		for _, sample := range s.Family(name) {
			if sample.Workload != "" {
				seen[sample.Namespace+"/"+sample.Workload] = struct{}{}
			}
		}
	}
	return len(seen)
}

// issueEvents indexes the latest Event per issue. An Event from a current
// agent names its issue and workload; one from an older agent is only known
// by the pod it hangs on.
type issueEvents struct {
	byIssue map[string]corev1.Event
	byPod   map[string]corev1.Event
}

func issueKey(namespace, workload, id string) string { return namespace + "/" + workload + "/" + id }

func indexIssueEvents(events []corev1.Event) issueEvents {
	idx := issueEvents{byIssue: map[string]corev1.Event{}, byPod: map[string]corev1.Event{}}
	keep := func(m map[string]corev1.Event, key string, e corev1.Event) {
		if cur, ok := m[key]; !ok || eventTime(e).After(eventTime(cur)) {
			m[key] = e
		}
	}
	for _, e := range events {
		ns := e.InvolvedObject.Namespace
		if ns == "" {
			ns = e.Namespace
		}
		id, workload := e.Annotations[alerting.AnnotationIssueID], e.Annotations[alerting.AnnotationWorkload]
		if id != "" && workload != "" {
			keep(idx.byIssue, issueKey(ns, workload, id), e)
			continue
		}
		keep(idx.byPod, ns+"/"+e.InvolvedObject.Name, e)
	}
	return idx
}

func (idx issueEvents) find(namespace, workload, id, pod string) (corev1.Event, bool) {
	if e, ok := idx.byIssue[issueKey(namespace, workload, id)]; ok {
		return e, true
	}
	if pod == "" {
		return corev1.Event{}, false
	}
	e, ok := idx.byPod[namespace+"/"+pod]
	return e, ok
}

func eventTime(e corev1.Event) time.Time {
	switch {
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	}
	return e.CreationTimestamp.Time
}

func eventStart(e corev1.Event) time.Time {
	if !e.FirstTimestamp.IsZero() {
		return e.FirstTimestamp.Time
	}
	return eventTime(e)
}

func issuesOf(s AgentScrape, events issueEvents, opts Options) []Issue {
	var out []Issue
	for _, sample := range s.Window.Cur.Family(familyIssueActive) {
		if sample.Value <= 0 || !opts.matches(sample.Namespace, sample.Workload) {
			continue
		}
		is := Issue{
			ID:        sample.Label("id"),
			Severity:  sample.Label("severity"),
			Namespace: sample.Namespace,
			Workload:  sample.Workload,
			Pod:       sample.Pod,
			Resource:  sample.Label("resource"),
			Node:      s.Agent.Node,
		}
		e, hasEvent := events.find(is.Namespace, is.Workload, is.ID, is.Pod)
		if live, ok := findLive(s, is); ok {
			since := live.Since
			is.Since = &since
			is.Message = live.Message
			is.Causes = live.Causes
			if is.Pod == "" {
				is.Pod = live.Pod
			}
		} else if hasEvent {
			since := eventStart(e)
			is.Since = &since
			is.Message = e.Message
		}
		if is.Pod == "" && hasEvent {
			is.Pod = e.InvolvedObject.Name
		}
		out = append(out, is)
	}
	return out
}

// findLive returns the live view of an issue the gauge reports, matched on
// what identifies it.
func findLive(s AgentScrape, is Issue) (LiveIssue, bool) {
	if !s.LiveRead {
		return LiveIssue{}, false
	}
	for _, l := range s.Live {
		if l.ID == is.ID && l.Namespace == is.Namespace && l.Workload == is.Workload &&
			l.Resource == is.Resource && (is.Pod == "" || l.Pod == is.Pod) {
			return l, true
		}
	}
	return LiveIssue{}, false
}

func severityRank(s string) int {
	switch s {
	case "emergency":
		return 4
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}

type workloadTotals struct {
	namespace, workload string
	perSecond           float64
	requests, errors    float64
	durations           []inspect.Delta
	issues              int
	worst               int
}

func addTraffic(into map[string]*workloadTotals, w inspect.Window, opts Options) {
	if !w.Ready() {
		return
	}
	interval := w.Interval()
	get := func(ns, wl string) *workloadTotals {
		key := ns + "/" + wl
		t, ok := into[key]
		if !ok {
			t = &workloadTotals{namespace: ns, workload: wl}
			into[key] = t
		}
		return t
	}
	for _, d := range w.Deltas(familyL7Requests) {
		if d.Reset || d.Sample.Workload == "" || !opts.matches(d.Sample.Namespace, d.Sample.Workload) {
			continue
		}
		t := get(d.Sample.Namespace, d.Sample.Workload)
		t.perSecond += d.PerSecond(interval)
		t.requests += d.Value
		if d.Sample.Label("outcome") == "error" {
			t.errors += d.Value
		}
	}
	for _, d := range w.Deltas(familyL7Duration) {
		if d.Reset || d.Sample.Workload == "" || !opts.matches(d.Sample.Namespace, d.Sample.Workload) {
			continue
		}
		t := get(d.Sample.Namespace, d.Sample.Workload)
		t.durations = append(t.durations, d)
	}
}

func rankWorkloads(totals map[string]*workloadTotals, top int) []Workload {
	type ranked struct {
		row   Workload
		worst int
	}
	rows := make([]ranked, 0, len(totals))
	for _, t := range totals {
		if t.requests == 0 && t.issues == 0 {
			continue
		}
		w := Workload{Namespace: t.namespace, Workload: t.workload, RequestsPerSecond: t.perSecond, Issues: t.issues}
		if t.requests > 0 {
			pct := t.errors / t.requests * 100
			w.ErrorPercent = &pct
		}
		if p95, ok := inspect.MergeDeltas(t.durations).Quantile(0.95); ok {
			ms := p95 * 1000
			w.P95Milliseconds = &ms
		}
		rows = append(rows, ranked{row: w, worst: t.worst})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].worst != rows[j].worst {
			return rows[i].worst > rows[j].worst
		}
		a, b := rows[i].row, rows[j].row
		if a.Issues != b.Issues {
			return a.Issues > b.Issues
		}
		if ea, eb := value(a.ErrorPercent), value(b.ErrorPercent); ea != eb {
			return ea > eb
		}
		if a.RequestsPerSecond != b.RequestsPerSecond {
			return a.RequestsPerSecond > b.RequestsPerSecond
		}
		return a.Namespace+"/"+a.Workload < b.Namespace+"/"+b.Workload
	})
	if top > 0 && len(rows) > top {
		rows = rows[:top]
	}
	out := make([]Workload, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.row)
	}
	return out
}

func value(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// String is the headline.
func (s Summary) String() string {
	return fmt.Sprintf("%d/%d agents healthy · %d active issues · %d workloads observed",
		s.AgentsHealthy, s.Agents, s.Issues, s.Workloads)
}

// Assess decides whether podtrace itself is healthy: the operator available,
// every fleet fully rolled out, and every agent capturing. Workload issues do
// not count; they are about the workloads, not about podtrace. listErr is
// the error from listing the components, if any: a user who may not list
// them still gets a verdict on the agents, with a warning that the rest was
// not checked.
func (r *Report) Assess(components []Component, listErr error) {
	r.Problems = nil
	r.Components = []ComponentStatus{}
	fleets := 0
	if listErr != nil {
		r.Warnings = append(r.Warnings, "could not check the operator and the fleets, so only the "+
			"agents were: "+oneLine(listErr.Error()))
	} else {
		operators := 0
		for _, c := range components {
			st := ComponentStatus{Kind: c.Kind, Name: c.Name, Fleet: c.Fleet, Desired: c.Desired, Ready: c.Ready, Updated: c.Updated, State: StateOK}
			switch {
			case c.Kind == KindFleet && c.Desired == 0:
				st.State = "no nodes"
				r.Warnings = append(r.Warnings, fmt.Sprintf("fleet %s schedules no agents; check its nodeSelector and tolerations", c.Name))
			case c.Desired == 0:
				st.State = "scaled to zero"
				r.Problems = append(r.Problems, fmt.Sprintf("the %s %s is scaled to zero", c.Kind, c.Name))
			case c.Ready < c.Desired || c.Updated < c.Desired:
				st.State = "rolling out"
				r.Problems = append(r.Problems, fmt.Sprintf("%s %s: %d of %d ready, %d updated", c.Kind, c.Name, c.Ready, c.Desired, c.Updated))
			}
			switch c.Kind {
			case KindOperator:
				operators++
			case KindFleet:
				fleets++
			}
			r.Components = append(r.Components, st)
		}
		if operators == 0 {
			r.Problems = append(r.Problems, "no podtrace operator found; check that podtrace is installed "+
				"and that --system-namespace names the namespace it runs in")
		}
		sort.Slice(r.Components, func(i, j int) bool {
			if r.Components[i].Kind != r.Components[j].Kind {
				return r.Components[i].Kind == KindOperator
			}
			return r.Components[i].Name < r.Components[j].Name
		})
	}
	switch {
	case len(r.Agents) > 0:
	case fleets > 0:
		r.Problems = append(r.Problems, "no agent pods are running yet")
	default:
		r.Problems = append(r.Problems, "no podtrace agents found; check that podtrace is installed "+
			"and that --system-namespace names the namespace it runs in")
	}
	for _, a := range r.Agents {
		if a.State == StateOK {
			continue
		}
		problem := fmt.Sprintf("agent on %s is %s", a.Node, a.State)
		if a.Reason != "" {
			problem += ": " + a.Reason
		}
		r.Problems = append(r.Problems, problem)
	}
	r.Healthy = len(r.Problems) == 0
}
