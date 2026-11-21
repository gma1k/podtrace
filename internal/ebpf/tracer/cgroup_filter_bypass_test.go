package tracer

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/events"
)

const bypassTestPID = 4242

func dispatchWithTracerBypass(tr *Tracer, ev *events.Event) bool {
	ch := make(chan *events.Event, 1)
	var collected, filtered, parsed atomic.Int64
	ec := &eventCounters{
		collected:         &collected,
		filtered:          &filtered,
		parsed:            &parsed,
		filteringDisabled: &tr.cgroupFilterBypassed,
	}
	tr.processAndDispatch(context.Background(), ev, ch, nil, ec, time.Now())
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func bypassTestContainer(t *testing.T, base, name string) (string, uint64) {
	t.Helper()
	container := filepath.Join(base, "kubepods.slice", testPodSlice, name)
	if err := os.MkdirAll(container, 0o750); err != nil {
		t.Fatal(err)
	}
	id, err := getCgroupIDFromPath(container)
	if err != nil {
		t.Fatal(err)
	}
	return container, id
}

func TestCgroupFilterBypassKeepsTheTargetSetAndAuthority(t *testing.T) {
	base := cgroupV2Base(t)
	container, id := bypassTestContainer(t, base, "cri-containerd-aaaa.scope")
	tr := gateTestTracer()
	if err := tr.AttachToCgroups([]string{container}); err != nil {
		t.Fatal(err)
	}

	if err := tr.bypassCgroupFilter(); err != nil {
		t.Fatal(err)
	}

	if !tr.cgroupFilterBypassed.Load() {
		t.Fatal("bypass flag not set")
	}
	if !tr.cgroupIDsAuthoritative.Load() {
		t.Fatal("bypass cleared cgroupIDsAuthoritative; with an empty id set that turns the kernel filter into deny-all")
	}
	if _, ok := tr.loadCgroupIDs()[id]; !ok {
		t.Fatalf("bypass dropped the target set: %v", tr.loadCgroupIDs())
	}
	if !tr.useUserspaceCgroupFilter.Load() {
		t.Fatal("bypass flipped the userspace filter mode, which no later attach restores")
	}
}

func TestCgroupFilterBypassAdmitsUntargetedEventsUntilTheTargetsChange(t *testing.T) {
	base := cgroupV2Base(t)
	first, firstID := bypassTestContainer(t, base, "cri-containerd-aaaa.scope")
	second, secondID := bypassTestContainer(t, base, "cri-containerd-bbbb.scope")
	tr := gateTestTracer()
	if err := tr.AttachToCgroups([]string{first}); err != nil {
		t.Fatal(err)
	}
	untargeted := &events.Event{Type: events.EventTCPSend, PID: bypassTestPID, CgroupID: secondID + 1000}

	if dispatchWithTracerBypass(tr, untargeted) {
		t.Fatal("an untargeted event was admitted before the bypass")
	}
	if err := tr.bypassCgroupFilter(); err != nil {
		t.Fatal(err)
	}
	if !dispatchWithTracerBypass(tr, untargeted) {
		t.Fatal("the bypass did not admit an untargeted event")
	}

	if err := tr.AttachToCgroups([]string{second}); err != nil {
		t.Fatal(err)
	}
	if tr.cgroupFilterBypassed.Load() {
		t.Fatal("a new target set left the bypass on")
	}
	if dispatchWithTracerBypass(tr, untargeted) {
		t.Fatal("an untargeted event was admitted after the targets changed")
	}
	if !dispatchWithTracerBypass(tr, &events.Event{Type: events.EventTCPSend, PID: bypassTestPID, CgroupID: secondID}) {
		t.Fatal("the new target was not admitted after the bypass ended")
	}
	if dispatchWithTracerBypass(tr, &events.Event{Type: events.EventTCPSend, PID: bypassTestPID, CgroupID: firstID}) {
		t.Fatal("the replaced target was still admitted")
	}
}

func TestCgroupFilterBypassEndsWhenTheTargetsAreCleared(t *testing.T) {
	base := cgroupV2Base(t)
	container, _ := bypassTestContainer(t, base, "cri-containerd-aaaa.scope")
	tr := gateTestTracer()
	if err := tr.AttachToCgroups([]string{container}); err != nil {
		t.Fatal(err)
	}
	if err := tr.bypassCgroupFilter(); err != nil {
		t.Fatal(err)
	}

	if err := tr.SetCgroups(nil); err != nil {
		t.Fatal(err)
	}

	if tr.cgroupFilterBypassed.Load() {
		t.Fatal("clearing the targets left the bypass on")
	}
}

func TestCgroupFilterBypassEndsOnAnAddedTarget(t *testing.T) {
	base := cgroupV2Base(t)
	first, _ := bypassTestContainer(t, base, "cri-containerd-aaaa.scope")
	second, _ := bypassTestContainer(t, base, "cri-containerd-bbbb.scope")
	tr := gateTestTracer()
	if err := tr.AttachToCgroups([]string{first}); err != nil {
		t.Fatal(err)
	}
	if err := tr.bypassCgroupFilter(); err != nil {
		t.Fatal(err)
	}

	if err := tr.AttachToCgroup(second); err != nil {
		t.Fatal(err)
	}

	if tr.cgroupFilterBypassed.Load() {
		t.Fatal("adding a target left the bypass on")
	}
}

func TestEventCountersShareTheTracerBypass(t *testing.T) {
	tr := gateTestTracer()
	ec := tr.newEventCounters()
	if ec.collected == nil || ec.filtered == nil || ec.parsed == nil {
		t.Fatal("a counter is missing")
	}
	tr.cgroupFilterBypassed.Store(true)
	if !ec.filteringDisabled.Load() {
		t.Fatal("the reader would not see a bypass set on the tracer")
	}
}

func TestAStalledFilterIsBypassed(t *testing.T) {
	tr := gateTestTracer()
	tr.bypassStalledCgroupFilter(tr.newEventCounters())
	if !tr.cgroupFilterBypassed.Load() {
		t.Fatal("the stalled filter was not bypassed")
	}
}

func TestABypassTheKernelRefusesIsReported(t *testing.T) {
	flag, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	_ = flag.Close()
	tr := gateTestTracer()
	tr.collection = &ebpf.Collection{Maps: map[string]*ebpf.Map{"cgroup_filter_enabled": flag}}

	if err := tr.bypassCgroupFilter(); err == nil {
		t.Fatal("a failed write to the kernel filter flag was swallowed")
	}
	tr.bypassStalledCgroupFilter(tr.newEventCounters())
}

func TestAStalledFilterIsBypassedWhenAllowed(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", "1")
	tr := gateTestTracer()
	if tr.handleStalledCgroupFilter(tr.newEventCounters(), false) {
		t.Fatal("the hint was reported as logged although the filter was bypassed")
	}
	if !tr.cgroupFilterBypassed.Load() {
		t.Fatal("the allowed bypass was not applied")
	}
}

func TestAStalledFilterIsOnlyHintedAtWhenNotAllowed(t *testing.T) {
	t.Setenv("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", "0")
	tr := gateTestTracer()
	ec := tr.newEventCounters()
	if !tr.handleStalledCgroupFilter(ec, false) {
		t.Fatal("the first stall did not record its hint")
	}
	if !tr.handleStalledCgroupFilter(ec, true) {
		t.Fatal("a later stall forgot the hint was logged")
	}
	if tr.cgroupFilterBypassed.Load() {
		t.Fatal("the filter was bypassed without being allowed")
	}
}
