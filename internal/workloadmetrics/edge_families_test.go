package workloadmetrics

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/inspect"
)

func TestTheInspectionsReadTheCallsThroughTheSink(t *testing.T) {
	sink, _ := newEdgeSink(t, staticPeer("payments", "shop"))
	at := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	before := inspect.TakeFrom(sink, at)
	call := l7Event("10.244.1.7")
	transfer := &events.Event{Type: events.EventTCPSend, Bytes: 512, PeerDstIP: "10.244.1.7", PeerDstPort: 5432, K8s: enriched()}
	if err := sink.Export(context.Background(), []*events.Event{call, transfer}); err != nil {
		t.Fatal(err)
	}
	after := inspect.TakeFrom(sink, at.Add(30*time.Second))

	edges := inspect.Edges(inspect.Window{Prev: before, Cur: after})
	if len(edges) != 1 {
		t.Fatalf("edges %+v, want one call to payments", edges)
	}
	if e := edges[0]; e.Workload != "checkout" || e.TargetService != "payments" || e.Requests != 1 {
		t.Errorf("edge %+v", e)
	}
}

func TestASinkWithoutAServiceMapServesNoCalls(t *testing.T) {
	sink, _ := newTestSink(t, 0)
	if got := sink.CollectFamilies(inspect.EdgeFamilies()); len(got) != 0 {
		t.Errorf("got %v from a sink with no peer resolver", got)
	}
}
