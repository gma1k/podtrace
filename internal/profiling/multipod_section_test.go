package profiling

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/events"
)

func slowDNSAt(at time.Time) []*events.Event {
	return []*events.Event{
		{Type: events.EventDNS, LatencyNS: uint64(2 * time.Second), Timestamp: clock.WallToBPFTimestamp(at), Target: "db.svc"},
		{Type: events.EventPageFault, PID: 9},
	}
}

func storeHeap(h *Handler, fn string) {
	h.mu.Lock()
	h.result = &CorrelatedResult{HeapProfile: &ProfileResult{
		Type:         ProfileHeap,
		Available:    true,
		TopFunctions: []FunctionSample{{Function: fn, Bytes: 4096, Count: 1}},
	}}
	h.mu.Unlock()
}

func TestMultiPodSectionPrintsTheSharedCorrelationOnce(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, []int{6060})
	storeHeap(m.handlers[0], "main.podOneAlloc")
	storeHeap(m.handlers[2], "main.podThreeAlloc")

	out := m.GenerateSection(slowDNSAt(time.Now()), time.Second)

	for marker, want := range map[string]int{
		"Performance Profiling Correlation:":                     1,
		"Slow events (> threshold) count":                        1,
		"Page faults observed":                                   1,
		"Tip: add":                                               1,
		"pprof endpoint: available (pod 10.0.0.1)":               1,
		"pprof endpoint: not found on target pod (pod 10.0.0.2)": 1,
		"pprof data from pod 10.0.0.3":                           1,
		"main.podOneAlloc":                                       1,
		"pprof data from pod 10.0.0.2":                           0,
	} {
		if got := strings.Count(out, marker); got != want {
			t.Errorf("%q appears %d times, want %d\n%s", marker, got, want, out)
		}
	}
}

func TestMultiPodSectionWithOnePodMatchesTheSinglePodSection(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1"}, []int{6060})
	storeHeap(m.handlers[0], "main.alloc")
	h := m.handlers[0]
	evs := slowDNSAt(time.Now())
	if got, want := m.GenerateSection(evs, time.Second), h.GenerateSection(evs, time.Second); got != want {
		t.Fatalf("one-pod multi section differs from the single-pod section:\n%s\n---\n%s", got, want)
	}
}

func TestEveryPodWithPprofSkipsTheTip(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2"}, []int{6060})
	storeHeap(m.handlers[0], "main.a")
	storeHeap(m.handlers[1], "main.b")
	if out := m.GenerateSection(nil, time.Second); strings.Contains(out, "Tip: add") {
		t.Fatalf("tip printed although every pod serves pprof:\n%s", out)
	}
}

func TestAttachPprofKeepsOnlyAnAvailableCPUProfile(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{6060})
	h.result = &CorrelatedResult{CPUProfile: &ProfileResult{Type: ProfileCPU, Available: false}}
	cr := &CorrelatedResult{}
	h.attachPprof(cr)
	if cr.CPUProfile != nil || cr.PprofAvailable {
		t.Fatalf("attachPprof = %+v, want an unavailable CPU profile left out", cr)
	}
}
