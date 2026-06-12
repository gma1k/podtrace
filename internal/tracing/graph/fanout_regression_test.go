package graph

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

// TestBuildFromTraces_FanOutEdges: edges were only created between spans
// ADJACENT in start order, so a parent fanning out to several children kept
// only the edge to its first child — every other parent/child edge was
// silently dropped from the request-flow graph.
func TestBuildFromTraces_FanOutEdges(t *testing.T) {
	base := time.Now()
	parent := &tracker.Span{
		TraceID: "t1", SpanID: "root", Service: "frontend",
		StartTime: base, Duration: 50 * time.Millisecond,
	}
	childA := &tracker.Span{
		TraceID: "t1", SpanID: "a", ParentSpanID: "root", Service: "auth",
		StartTime: base.Add(1 * time.Millisecond), Duration: 5 * time.Millisecond,
	}
	// An unrelated span starts between the two children, breaking adjacency.
	unrelated := &tracker.Span{
		TraceID: "t1", SpanID: "x", Service: "cron",
		StartTime: base.Add(2 * time.Millisecond), Duration: time.Millisecond,
	}
	childB := &tracker.Span{
		TraceID: "t1", SpanID: "b", ParentSpanID: "root", Service: "billing",
		StartTime: base.Add(3 * time.Millisecond), Duration: 5 * time.Millisecond,
	}

	g := NewGraphBuilder().BuildFromTraces([]*tracker.Trace{{
		TraceID: "t1",
		Spans:   []*tracker.Span{parent, childA, unrelated, childB},
	}})

	edges := map[string]bool{}
	for _, e := range g.Edges {
		edges[e.Source+"->"+e.Target] = true
	}
	if !edges["frontend->auth"] {
		t.Error("missing frontend->auth edge")
	}
	if !edges["frontend->billing"] {
		t.Error("missing frontend->billing edge (fan-out child not adjacent to parent)")
	}
	if len(edges) != 2 {
		t.Errorf("got edges %v, want exactly the two fan-out edges", edges)
	}
}
