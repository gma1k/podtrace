package tracer

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/redactor"
)

func TestCgroupAllows_HonorsCgroupIDAllowlist(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	tr.storeCgroupIDs(map[uint64]struct{}{100: {}})

	if !tr.cgroupAllows(&events.Event{CgroupID: 100, PID: 1}) {
		t.Error("an event whose cgroup is in the allowlist must be allowed")
	}
	if tr.cgroupAllows(&events.Event{CgroupID: 200, PID: 1}) {
		t.Error("an event whose cgroup is NOT in the allowlist must be denied (a --container-narrowed session must not emit sibling-container timeouts)")
	}
}

func TestCgroupAllows_NoFilterConfiguredAllowsAll(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	if !tr.cgroupAllows(&events.Event{CgroupID: 7, PID: 1}) {
		t.Error("with no cgroup filter configured, events must be allowed")
	}
}

func TestCgroupAllows_IdleDenyDenies(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	tr.denyWhenNoTargets.Store(true)
	if tr.cgroupAllows(&events.Event{CgroupID: 7, PID: 1}) {
		t.Error("with deny-when-no-targets and no targets, events must be denied")
	}
}

func TestCgroupAllows_UserspaceFilter(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	tr.useUserspaceCgroupFilter.Store(true)
	tr.filter.SetCgroupPath("/kubepods/podX")
	if tr.cgroupAllows(&events.Event{CgroupID: 0, PID: 999999}) {
		t.Error("userspace filter must deny a pid outside the target cgroup")
	}
}

func TestBuildDNSTimeoutEvent_SanitizesAndGates(t *testing.T) {
	tr := newAttributionTestTracer()
	tr.filter = filter.NewCgroupFilter()
	tr.piiRedactor = redactor.Default()
	tr.storeCgroupIDs(map[uint64]struct{}{100: {}})

	var val dnsQueryState
	copy(val.Name[:], "evil\x1b[31m.example\x00")
	val.PID = 4242

	allowed := tr.buildDNSTimeoutEvent(dnsFlowKey{CgroupID: 100}, val, 2000, 1000)
	if allowed == nil {
		t.Fatal("an event in the cgroup allowlist must be emitted")
	}
	if strings.ContainsAny(allowed.Target, "\x1b") {
		t.Errorf("QNAME must be terminal-sanitized, got %q", allowed.Target)
	}

	denied := tr.buildDNSTimeoutEvent(dnsFlowKey{CgroupID: 999}, val, 2000, 1000)
	if denied != nil {
		t.Error("an event outside the cgroup allowlist must be dropped (nil)")
	}
}
