package graph

import (
	"strings"
	"sync"
	"testing"
)

func TestToDOT_EscapesQuotesAndNewlines(t *testing.T) {
	g := &RequestFlowGraph{
		Nodes: []Node{{ID: `evil"node`, Service: "svc\nline", RequestCount: 1}},
		Edges: []Edge{{Source: `s"rc`, Target: "tgt\n2", RequestCount: 1}},
	}
	out := g.ToDOT()

	for _, raw := range []string{`evil"node`, `s"rc`, "svc\nline", "tgt\n2"} {
		if strings.Contains(out, raw) {
			t.Errorf("unescaped %q leaked into DOT:\n%s", raw, out)
		}
	}
	for _, esc := range []string{`evil\"node`, `s\"rc`, `svc\nline`, `tgt\n2`} {
		if !strings.Contains(out, esc) {
			t.Errorf("expected escaped %q in DOT:\n%s", esc, out)
		}
	}
}

func TestBuildFromTraces_ConcurrentSafe(t *testing.T) {
	gb := NewGraphBuilder()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = gb.BuildFromTraces(nil)
			}
		}()
	}
	wg.Wait()
}
