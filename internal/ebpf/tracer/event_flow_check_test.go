package tracer

import (
	"testing"
	"time"
)

func eventFlowCounters(tr *Tracer, parsed, collected int64) *eventCounters {
	ec := tr.newEventCounters()
	ec.parsed.Store(parsed)
	ec.collected.Store(collected)
	ec.filtered.Store(parsed - collected)
	return ec
}

func TestEventFlowCheckBypassesAStalledFilterWhenAllowed(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", "1")
	tr := gateTestTracer()
	if tr.checkEventFlow(eventFlowCounters(tr, 50, 0), 11*time.Second, false) {
		t.Fatal("a bypass reported the hint as logged")
	}
	if !tr.cgroupFilterBypassed.Load() {
		t.Fatal("a stalled filter was not bypassed")
	}
}

func TestEventFlowCheckHintsAtAStalledFilterWhenNotAllowed(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", "0")
	tr := gateTestTracer()
	if !tr.checkEventFlow(eventFlowCounters(tr, 50, 0), 11*time.Second, false) {
		t.Fatal("the stall hint was not recorded")
	}
	if tr.cgroupFilterBypassed.Load() {
		t.Fatal("the filter was bypassed without being allowed")
	}
}

func TestEventFlowCheckLeavesTheHintAloneOtherwise(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", "1")
	for name, tc := range map[string]struct {
		parsed, collected int64
		elapsed           time.Duration
		bypassed          bool
		userspaceFilter   bool
	}{
		"nothing parsed yet":                     {parsed: 0, elapsed: 16 * time.Second},
		"nothing parsed but still starting":      {parsed: 0, elapsed: 5 * time.Second},
		"few events all filtered":                {parsed: 5, elapsed: 11 * time.Second},
		"all filtered after a bypass":            {parsed: 50, elapsed: 11 * time.Second, bypassed: true},
		"all filtered by the userspace filter":   {parsed: 5, elapsed: 11 * time.Second, userspaceFilter: true},
		"events flowing":                         {parsed: 50, collected: 40, elapsed: 30 * time.Second},
		"all filtered but too early to conclude": {parsed: 50, elapsed: 5 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			tr := gateTestTracer()
			tr.cgroupFilterBypassed.Store(tc.bypassed)
			tr.useUserspaceCgroupFilter.Store(tc.userspaceFilter)
			for _, hint := range []bool{false, true} {
				if got := tr.checkEventFlow(eventFlowCounters(tr, tc.parsed, tc.collected), tc.elapsed, hint); got != hint {
					t.Fatalf("hint %v became %v", hint, got)
				}
			}
			if tr.cgroupFilterBypassed.Load() != tc.bypassed {
				t.Fatal("the bypass changed without a stalled filter")
			}
		})
	}
}
