package tracer

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/sysfs"
)

// Attribution sources reported to podtrace_attribution_total.
const (
	attributionSourceEventComm    = "event_comm"
	attributionSourceCorrelator   = "correlator"
	attributionSourceProcFallback = "proc_fallback"
	attributionSourceNone         = "none"
)

// attributeProcessName fills event.ProcessName for events that arrived
// without a kernel-captured comm, the cgroup_skb producers (DNS, QUIC),
// which cannot call bpf_get_current_comm — and reports where the name
// came from.
func (t *Tracer) attributeProcessName(event *events.Event) string {
	if event.ProcessName != "" {
		return attributionSourceEventComm
	}
	if !t.attributionCorrelatorDisabled {
		name, ok, reuseSuspected := t.attributionTable.Lookup(event.PID, event.CgroupID)
		if ok {
			event.ProcessName = name
			return attributionSourceCorrelator
		}
		if reuseSuspected {
			metricsexporter.RecordAttributionPidReuseSuspected()
		}
	}
	if !pidInEventCgroup(event) {
		return attributionSourceNone
	}
	event.ProcessName = t.getProcessNameQuick(event.PID)
	if event.ProcessName != "" {
		return attributionSourceProcFallback
	}
	return attributionSourceNone
}

// pidInEventCgroup reports whether the event's pid may name it.
func pidInEventCgroup(event *events.Event) bool {
	if event.CgroupID == 0 {
		return true
	}
	cgroupID, ok := procCgroupID(event.PID)
	return !ok || cgroupID == event.CgroupID
}

// procCgroupID resolves a pid's cgroup v2 id from /proc/<pid>/cgroup;
// replaceable so tests need no real processes.
var procCgroupID = func(pid uint32) (uint64, bool) {
	data, err := procfs.ReadFile(strconv.FormatUint(uint64(pid), 10) + "/cgroup")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok || !strings.HasPrefix(path, "/") {
			continue
		}
		hostPath, ok := hostCgroupPath(path)
		if !ok {
			return 0, false
		}
		id, err := getCgroupIDFromPath(filepath.Join(config.CgroupBasePath, hostPath))
		if err != nil || id == 0 {
			return 0, false
		}
		return id, true
	}
	return 0, false
}

// hostCgroupPath turns a cgroup path as /proc/<pid>/cgroup shows it into
// one under the host's cgroup root.
func hostCgroupPath(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	climbs := 0
	for climbs < len(parts) && parts[climbs] == ".." {
		climbs++
	}
	for _, p := range parts[climbs:] {
		if p == ".." {
			return "", false
		}
	}
	if climbs == 0 {
		return path, true
	}
	root, ok := cgroupNamespaceRoot()
	if !ok {
		return "", false
	}
	return filepath.Join("/", root, path), true
}

// cgroupNamespaceRoot is where this process's cgroup namespace root sits in
// the host hierarchy: the cgroup that lists this process, found once.
var cgroupNamespaceRoot = sync.OnceValues(defaultCgroupNamespaceRoot)

func defaultCgroupNamespaceRoot() (string, bool) {
	return sysfs.CgroupFindProcess(os.Getpid())
}

// recordAttributionOutcome feeds the attribution table and the metrics
// from one dispatched event.
func (t *Tracer) recordAttributionOutcome(event *events.Event, source string) {
	if source == attributionSourceEventComm && event.ProcessName != "" {
		t.attributionTable.Record(event.PID, event.CgroupID, event.ProcessName)
	}
	metricsexporter.RecordAttribution(source, attributionEventKind(event.Type))
}

// attributionEventKind buckets event types for the attribution metric:
// dns and quic are the cgroup_skb-sourced kinds the attribution work
// targets, everything else is the baseline.
func attributionEventKind(t events.EventType) string {
	switch t {
	case events.EventDNS, events.EventDNSQuery:
		return "dns"
	case events.EventHTTP3:
		return "quic"
	default:
		return "other"
	}
}
