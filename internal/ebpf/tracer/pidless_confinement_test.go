package tracer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/events"
)

func newConfinedTracer(t *testing.T) *Tracer {
	t.Helper()
	tr := newDispatchTestTracer()
	tr.filter = filter.NewCgroupFilter()
	tr.filter.SetCgroupPaths([]string{"/sys/fs/cgroup/kubepods.slice/pod-target.slice"})
	tr.useUserspaceCgroupFilter.Store(true)
	return tr
}

func dispatchConfined(t *testing.T, tr *Tracer, ev *events.Event) bool {
	t.Helper()
	ch := make(chan *events.Event, 1)
	var collected, filtered, parsed atomic.Int64
	var filteringDisabled atomic.Bool
	ec := &eventCounters{
		collected:         &collected,
		filtered:          &filtered,
		parsed:            &parsed,
		filteringDisabled: &filteringDisabled,
	}
	tr.processAndDispatch(context.Background(), ev, ch, nil, ec, time.Now())
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestAnEventWithNoOwningTaskIsAdmittedOnItsCgroup(t *testing.T) {
	tr := newConfinedTracer(t)
	ev := &events.Event{Type: events.EventTCPRTT, PID: 0, CgroupID: 4242, LatencyNS: 140_000}

	if !dispatchConfined(t, tr, ev) {
		t.Fatal("a sock_ops RTT sample carrying its socket's cgroup was dropped.\n\n" +
			"An RTT callback has no current task, so there is no PID to check and " +
			"IsPIDInCgroup(0) rejects it. The kernel already tested this exact cgroup id " +
			"against the target set before emitting; userspace must confine it on that " +
			"key, not discard it for lacking a different one.")
	}
}

func TestAnEventWithNeitherPIDNorCgroupIsStillRefused(t *testing.T) {
	tr := newConfinedTracer(t)
	ev := &events.Event{Type: events.EventTCPRTT, PID: 0, CgroupID: 0}

	if dispatchConfined(t, tr, ev) {
		t.Fatal("an event with no PID and no cgroup got through a live confinement " +
			"filter.\n\nThe PID-less branch exists for events that carry a cgroup " +
			"instead. One that carries neither has no identity to confine on and must " +
			"fall through to the PID check, which refuses it. Admitting it would be a " +
			"blanket exemption for PID 0, which is exactly what the branch must not be.")
	}
}

func TestAnOrdinaryEventStillFacesThePIDCheck(t *testing.T) {
	tr := newConfinedTracer(t)
	ev := &events.Event{Type: events.EventTCPSend, PID: deadPID, CgroupID: 4242}

	if dispatchConfined(t, tr, ev) {
		t.Fatal("an event with a real PID outside every target cgroup was admitted " +
			"because it also carried a cgroup id.\n\nThe PID-less branch must only " +
			"catch PID 0. A task that exists is confined by where that task lives, " +
			"and carrying a cgroup id is not a way around that.")
	}
}

func TestThePIDlessBranchDoesNotOverrideTheCgroupIDSet(t *testing.T) {
	tr := newConfinedTracer(t)
	tr.storeCgroupIDs(map[uint64]struct{}{7: {}})
	ev := &events.Event{Type: events.EventTCPRTT, PID: 0, CgroupID: 4242}

	if dispatchConfined(t, tr, ev) {
		t.Fatal("a PID-less event from cgroup 4242 was admitted while the target set " +
			"is {7}.\n\nWhen target cgroup ids are known they are the authority, and " +
			"they are checked before the PID-less branch. A PID-less event from a " +
			"cgroup outside that set must be refused like any other.")
	}
}

func TestAPIDlessEventFromATargetCgroupIsAdmittedByTheIDSet(t *testing.T) {
	tr := newConfinedTracer(t)
	tr.storeCgroupIDs(map[uint64]struct{}{4242: {}})
	ev := &events.Event{Type: events.EventTCPRTT, PID: 0, CgroupID: 4242}

	if !dispatchConfined(t, tr, ev) {
		t.Fatal("a PID-less event from a cgroup in the target set was refused")
	}
}

func TestAnIdleNodeInDenyModeDropsEvenAPIDlessEvent(t *testing.T) {
	tr := newDispatchTestTracer()
	tr.filter = filter.NewCgroupFilter()
	tr.denyWhenNoTargets.Store(true)
	ev := &events.Event{Type: events.EventTCPRTT, PID: 0, CgroupID: 4242}

	if dispatchConfined(t, tr, ev) {
		t.Fatal("a node with no targets in deny mode admitted a sock_ops RTT sample.\n\n" +
			"The PID-less branch admits an event on its cgroup id, but only after the idle " +
			"deny has had its say: with nothing targeted there is no cgroup the sample may " +
			"belong to, and admitting it would export another tenant's traffic.")
	}
}
