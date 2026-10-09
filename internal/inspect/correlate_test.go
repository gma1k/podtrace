package inspect

import (
	"reflect"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func edgeLabels(workload, targetNamespace, target string, extra ...*dto.LabelPair) []*dto.LabelPair {
	return append([]*dto.LabelPair{
		label("namespace", "shop"),
		label("workload", workload),
		label("target_namespace", targetNamespace),
		label("target_service", target),
	}, extra...)
}

func edgeWindow(prev, cur []*dto.MetricFamily) Window {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	return Window{Prev: TakeFamilies(prev, at), Cur: TakeFamilies(cur, at.Add(30*time.Second))}
}

func TestEdgesSumTheWindowsRequestsAndBytesPerCall(t *testing.T) {
	prev := []*dto.MetricFamily{
		counterFamily(familyEdgeRequests,
			counter(10, edgeLabels("front", "shop", "backend", label("outcome", "ok"))...),
			counter(1, edgeLabels("front", "shop", "backend", label("outcome", "error"))...)),
		counterFamily(familyEdgeBytes,
			counter(100, edgeLabels("front", "data", "postgres", label("direction", "sent"))...)),
	}
	cur := []*dto.MetricFamily{
		counterFamily(familyEdgeRequests,
			counter(16, edgeLabels("front", "shop", "backend", label("outcome", "ok"))...),
			counter(3, edgeLabels("front", "shop", "backend", label("outcome", "error"))...)),
		counterFamily(familyEdgeBytes,
			counter(400, edgeLabels("front", "data", "postgres", label("direction", "sent"))...),
			counter(50, edgeLabels("front", "data", "postgres", label("direction", "received"))...)),
	}
	got := Edges(edgeWindow(prev, cur))
	want := []Edge{
		{Namespace: "shop", Workload: "front", TargetNamespace: "data", TargetService: "postgres", Bytes: 350},
		{Namespace: "shop", Workload: "front", TargetNamespace: "shop", TargetService: "backend", Requests: 8},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAnEdgeWithoutTrafficInTheWindowIsNotACall(t *testing.T) {
	fam := []*dto.MetricFamily{counterFamily(familyEdgeRequests,
		counter(10, edgeLabels("front", "shop", "backend", label("outcome", "ok"))...))}
	if got := Edges(edgeWindow(fam, fam)); len(got) != 0 {
		t.Errorf("got %+v, want no edges", got)
	}
}

func TestAnEdgeToTheOverflowBucketIsNotACall(t *testing.T) {
	cur := []*dto.MetricFamily{counterFamily(familyEdgeRequests,
		counter(5, edgeLabels("front", unknownTargetNamespace, "other", label("outcome", "ok"))...),
		counter(5, edgeLabels("front", "shop", "", label("outcome", "ok"))...))}
	if got := Edges(edgeWindow(nil, cur)); len(got) != 0 {
		t.Errorf("got %+v, want no edges", got)
	}
}

func TestEdgesNeedTwoGathers(t *testing.T) {
	if got := Edges(Window{}); got != nil {
		t.Errorf("got %+v from an empty window", got)
	}
}

func TestDependenciesResolveServicesToTheirWorkloads(t *testing.T) {
	edges := []Edge{
		{Namespace: "shop", Workload: "front", TargetNamespace: "shop", TargetService: "backend", Requests: 1},
		{Namespace: "shop", Workload: "front", TargetNamespace: "shop", TargetService: "backend-canary", Requests: 1},
		{Namespace: "shop", Workload: "front", TargetNamespace: "data", TargetService: "external", Bytes: 1},
	}
	workloads := map[string][]string{"shop/backend": {"backend"}, "shop/backend-canary": {"backend", "backend-canary"}}
	deps := Dependencies(edges, func(ns, svc string) []string { return workloads[ns+"/"+svc] })
	want := []detector.IssueRef{
		{Namespace: "shop", Workload: "backend"},
		{Namespace: "shop", Workload: "backend-canary"},
	}
	if got := deps("shop", "front"); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := deps("shop", "backend"); got != nil {
		t.Errorf("backend calls nothing, got %v", got)
	}
}

type togglingRule struct {
	on map[detector.ID]bool
}

func (r *togglingRule) rule(id detector.ID) Rule {
	return Rule{ID: id, Eval: func(Window, Thresholds) []detector.Issue {
		if !r.on[id] {
			return nil
		}
		return []detector.Issue{{
			ID:       id,
			Severity: alerting.SeverityWarning,
			Subject:  detector.Subject{Namespace: "shop", Workload: "api", Pod: "api-1"},
			Message:  string(id),
		}}
	}}
}

func TestAnIssueActivatesWithTheCausesActiveAlongsideIt(t *testing.T) {
	toggle := &togglingRule{on: map[detector.ID]bool{detector.IDL7LatencyDegraded: true, detector.IDDBPoolSaturated: true}}
	h := newHarness(t, toggle.rule(detector.IDL7LatencyDegraded), toggle.rule(detector.IDDBPoolSaturated))
	pool := detector.IssueRef{ID: detector.IDDBPoolSaturated, Namespace: "shop", Workload: "api"}

	activated := h.evaluate(t)
	byID := map[detector.ID]detector.Issue{}
	for _, is := range activated {
		byID[is.ID] = is
	}
	if want := []detector.Cause{{IssueRef: pool}}; !reflect.DeepEqual(byID[detector.IDL7LatencyDegraded].Causes, want) {
		t.Errorf("latency activated with causes %v, want %v", byID[detector.IDL7LatencyDegraded].Causes, want)
	}
	if len(byID[detector.IDDBPoolSaturated].Causes) != 0 {
		t.Errorf("the pool activated with causes %v", byID[detector.IDDBPoolSaturated].Causes)
	}
	for _, is := range h.observer.activated {
		if is.ID == detector.IDL7LatencyDegraded && len(is.Causes) != 1 {
			t.Errorf("the observer was told about latency without its cause: %v", is.Causes)
		}
	}
}

func TestActiveIssuesFollowTheirCausesAsTheyComeAndGo(t *testing.T) {
	toggle := &togglingRule{on: map[detector.ID]bool{detector.IDL7LatencyDegraded: true}}
	h := newHarness(t, toggle.rule(detector.IDL7LatencyDegraded), toggle.rule(detector.IDDBPoolSaturated))
	causesOfLatency := func() []detector.Cause {
		for _, a := range h.engine.ActiveIssues() {
			if a.ID == detector.IDL7LatencyDegraded {
				return a.Causes
			}
		}
		t.Fatal("latency is not active")
		return nil
	}

	h.evaluate(t)
	if got := causesOfLatency(); len(got) != 0 {
		t.Errorf("latency alone has causes %v", got)
	}

	toggle.on[detector.IDDBPoolSaturated] = true
	h.advance(30 * time.Second)
	h.evaluate(t)
	if got := causesOfLatency(); len(got) != 1 || got[0].ID != detector.IDDBPoolSaturated {
		t.Errorf("after the pool saturated, latency causes %v", got)
	}

	toggle.on[detector.IDDBPoolSaturated] = false
	h.advance(30 * time.Second)
	h.evaluate(t)
	if got := causesOfLatency(); len(got) != 0 {
		t.Errorf("after the pool recovered, latency still has causes %v", got)
	}
}

func TestACauseNeverChangesWhetherAnIssueFiresOrClears(t *testing.T) {
	toggle := &togglingRule{on: map[detector.ID]bool{detector.IDL7LatencyDegraded: true, detector.IDDBPoolSaturated: true}}
	h := newHarness(t, toggle.rule(detector.IDL7LatencyDegraded), toggle.rule(detector.IDDBPoolSaturated))
	if got := len(h.evaluate(t)); got != 2 {
		t.Fatalf("%d issues activated, want both", got)
	}
	toggle.on[detector.IDDBPoolSaturated] = false
	h.advance(30 * time.Second)
	h.evaluate(t)
	if got := len(h.engine.ActiveIssues()); got != 1 {
		t.Errorf("%d issues active after the cause cleared, want the symptom still firing", got)
	}
	if len(h.observer.cleared) != 1 || h.observer.cleared[0].ID != detector.IDDBPoolSaturated {
		t.Errorf("cleared %v, want only the pool", h.observer.cleared)
	}
}

func TestTheEngineKeepsTheLatestWindowsEdges(t *testing.T) {
	h := newHarness(t, (&togglingRule{}).rule(detector.IDL7LatencyDegraded))
	h.serve(counterFamily(familyEdgeRequests, counter(1, edgeLabels("front", "shop", "backend", label("outcome", "ok"))...)))
	h.evaluate(t)
	if got := h.engine.Edges(); len(got) != 0 {
		t.Errorf("one gather produced edges %v", got)
	}
	h.serve(counterFamily(familyEdgeRequests, counter(4, edgeLabels("front", "shop", "backend", label("outcome", "ok"))...)))
	h.advance(30 * time.Second)
	h.evaluate(t)
	want := []Edge{{Namespace: "shop", Workload: "front", TargetNamespace: "shop", TargetService: "backend", Requests: 3}}
	if got := h.engine.Edges(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

type recordingSource struct{ asked []string }

func (s *recordingSource) CollectFamilies(names []string) map[string][]*dto.Metric {
	s.asked = names
	return nil
}

func (s *recordingSource) RuleFamilies() []string { return []string{familyL7Requests} }

func TestASnapshotAlsoReadsTheEdges(t *testing.T) {
	src := &recordingSource{}
	TakeFrom(src, time.Now())
	want := []string{familyL7Requests, familyEdgeRequests, familyEdgeBytes}
	if !reflect.DeepEqual(src.asked, want) {
		t.Errorf("asked for %v, want %v", src.asked, want)
	}
}

func TestEdgesAreOrderedByCallerThenTarget(t *testing.T) {
	cur := []*dto.MetricFamily{counterFamily(familyEdgeRequests,
		counter(1, edgeLabels("zeta", "shop", "a", label("outcome", "ok"))...),
		counter(1, edgeLabels("alpha", "shop", "b", label("outcome", "ok"))...),
		counter(1, edgeLabels("alpha", "shop", "a", label("outcome", "ok"))...))}
	got := Edges(edgeWindow(nil, cur))
	var order []string
	for _, e := range got {
		order = append(order, e.Workload+"->"+e.TargetService)
	}
	if want := []string{"alpha->a", "alpha->b", "zeta->a"}; !reflect.DeepEqual(order, want) {
		t.Errorf("order %v, want %v", order, want)
	}
}
