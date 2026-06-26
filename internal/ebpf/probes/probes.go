package probes

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/hostfs"
	"github.com/podtrace/podtrace/internal/ldsoconf"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/procfs"
)

// mandatoryProbes must all attach successfully; failure returns an actionable error.
var mandatoryProbes = map[string]string{
	"kprobe_tcp_connect":       "tcp_v4_connect",
	"kretprobe_tcp_connect":    "tcp_v4_connect",
	"kprobe_tcp_v6_connect":    "tcp_v6_connect",
	"kretprobe_tcp_v6_connect": "tcp_v6_connect",
	"kprobe_tcp_sendmsg":       "tcp_sendmsg",
	"kretprobe_tcp_sendmsg":    "tcp_sendmsg",
	"kprobe_tcp_recvmsg":       "tcp_recvmsg",
	"kretprobe_tcp_recvmsg":    "tcp_recvmsg",
	"kprobe_vfs_write":         "vfs_write",
	"kretprobe_vfs_write":      "vfs_write",
	"kprobe_vfs_read":          "vfs_read",
	"kretprobe_vfs_read":       "vfs_read",
}

// optionalProbes are attached when available; failure is logged but does not abort.
// Kernel symbol names can change across versions (e.g. do_futex renamed in 5.16+),
// so these degrade gracefully.
var optionalProbes = map[string]string{
	"kprobe_udp_sendmsg":       "udp_sendmsg",
	"kretprobe_udp_sendmsg":    "udp_sendmsg",
	"kprobe_udp_recvmsg":       "udp_recvmsg",
	"kretprobe_udp_recvmsg":    "udp_recvmsg",
	"kprobe_vfs_fsync":         "vfs_fsync",
	"kretprobe_vfs_fsync":      "vfs_fsync",
	"kprobe_do_futex":          "do_futex",
	"kretprobe_do_futex":       "do_futex",
	"kprobe_do_sys_openat2":    "do_sys_openat2",
	"kretprobe_do_sys_openat2": "do_sys_openat2",
	"kprobe_vfs_unlink":        "vfs_unlink",
	"kprobe_close_fd":          "close_fd",
	"kretprobe_vfs_unlink":     "vfs_unlink",
	"kprobe_vfs_rename":        "vfs_rename",
	"kretprobe_vfs_rename":     "vfs_rename",
}

func attachKprobe(progName, symbol string, prog *ebpf.Program) (link.Link, error) {
	if strings.HasPrefix(progName, "kretprobe_") {
		return link.Kretprobe(symbol, prog, nil)
	}
	return link.Kprobe(symbol, prog, nil)
}

// AttachProbes attaches every probe whose program is present in the
// collection and returns a flat slice of the resulting links.
func AttachProbes(coll *ebpf.Collection) ([]link.Link, error) {
	groups, err := AttachProbesByGroup(coll)
	if err != nil {
		return nil, err
	}
	return flattenGroupedLinks(groups), nil
}

// flattenGroupedLinks concatenates a group→links map into a single
// slice.
func flattenGroupedLinks(groups map[ProbeGroup][]link.Link) []link.Link {
	var out []link.Link
	for _, g := range allProbeGroups() {
		out = append(out, groups[g]...)
	}
	return out
}

// allProbeGroups returns the canonical ordering of probe groups. New
// groups added to groups.go must be added here too.
func allProbeGroups() []ProbeGroup {
	return []ProbeGroup{
		GroupNetwork, GroupFileSystem, GroupDatabase, GroupTLS,
		GroupMemory, GroupCPU, GroupPool, GroupCache,
		GroupMessaging, GroupFastCGI, GroupCrypto,
	}
}

// AttachProbesByGroup performs the same attach work as AttachProbes but
// returns the resulting links bucketed by the ProbeGroup each program
// belongs to.
func AttachProbesByGroup(coll *ebpf.Collection) (map[ProbeGroup][]link.Link, error) {
	groups := map[ProbeGroup][]link.Link{}
	appendLink := func(progName string, l link.Link) {
		g := GroupForProbe(progName)
		groups[g] = append(groups[g], l)
	}
	closeAll := func() {
		for _, ls := range groups {
			for _, l := range ls {
				_ = l.Close()
			}
		}
	}

	// --- Mandatory kprobes: all must attach or we return an error. ---
	for progName, symbol := range mandatoryProbes {
		prog := coll.Programs[progName]
		if prog == nil {
			logger.Debug("Mandatory probe program not found in collection, skipping",
				zap.String("prog", progName))
			continue
		}

		l, err := attachKprobe(progName, symbol, prog)
		if err != nil {
			reportAttachFailure(progName, symbol, true, err)
			closeAll()
			return nil, fmt.Errorf(
				"%w\n\n"+
					"Hint: mandatory kprobe %q could not attach to kernel symbol %q.\n"+
					"  • Verify symbol exists: grep -w %q /proc/kallsyms\n"+
					"  • Check for BPF denials: dmesg | grep -i bpf\n"+
					"  • Kernel 5.8+ required (current: %s)\n"+
					"  • On GKE Autopilot / AWS Fargate kprobes are not allowed; use a standard node pool.\n"+
					"  • On OpenShift ensure the pod SCC allows CAP_BPF and CAP_SYS_ADMIN",
				NewProbeAttachError(progName, err), progName, symbol, symbol, kernelVersionString())
		}
		appendLink(progName, l)
		logger.Debug("Mandatory probe attached", zap.String("prog", progName), zap.String("symbol", symbol))
	}

	var skippedOptional []string

	// --- Optional kprobes: log failures but continue. ---
	for progName, symbol := range optionalProbes {
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}

		l, err := attachKprobe(progName, symbol, prog)
		if err != nil {
			reportAttachFailure(progName, symbol, false, err)
			skippedOptional = append(skippedOptional, fmt.Sprintf("%s->%s", progName, symbol))
			logger.Debug("Optional probe unavailable (skipping)",
				zap.String("prog", progName), zap.String("symbol", symbol), zap.Error(err))
			continue
		}
		appendLink(progName, l)
		logger.Debug("Optional probe attached", zap.String("prog", progName), zap.String("symbol", symbol))
	}

	if len(skippedOptional) > 0 {
		logger.Info("Some optional probes unavailable (non-critical features degraded)",
			zap.Strings("skipped", skippedOptional))
	}

	for _, tp := range tracepointProbes {
		if l, ok := attachTracepointSpec(coll, tp); ok {
			appendLink(tp.prog, l)
		}
	}

	return groups, nil
}

// tracepointSpec describes a tracepoint-backed BPF program and how to
// attach it.
type tracepointSpec struct {
	prog     string
	category string
	event    string
	failMsg  string
}

// tracepointProbes is the single source of truth for every tracepoint
// program, shared by AttachProbesByGroup (startup) and AttachProbeGroup
// (hot re-attach) so the two paths can never drift.
var tracepointProbes = []tracepointSpec{
	{"tracepoint_sched_switch", "sched", "sched_switch", "CPU/scheduling tracking unavailable"},
	{"tracepoint_inet_sock_set_state", "sock", "inet_sock_set_state", "TCP state-change tracking unavailable"},
	{"tracepoint_tcp_retransmit_skb", "tcp", "tcp_retransmit_skb", "TCP retransmission tracking unavailable"},
	{"tracepoint_net_dev_xmit", "net", "net_dev_xmit", "Network device error tracking unavailable"},
	{"tracepoint_page_fault_user", "exceptions", "page_fault_user", "Page fault tracking unavailable"},
	{"tracepoint_oom_mark_victim", "oom", "mark_victim", "OOM kill tracking unavailable"},
	{"tracepoint_sched_process_fork", "sched", "sched_process_fork", "Process fork tracking unavailable"},
	{"tracepoint_sched_process_exec", "sched", "sched_process_exec", "Process exec tracking unavailable"},
	{"tracepoint_sys_enter_bind", "syscalls", "sys_enter_bind", "AF_ALG crypto-socket detection unavailable"},
}

// attachTracepointSpec attaches one tracepoint, returning (link, true) on
// success or (nil, false) if the program is absent or the attach fails
// (logged, non-fatal — tracepoints are best-effort).
func attachTracepointSpec(coll *ebpf.Collection, tp tracepointSpec) (link.Link, bool) {
	prog := coll.Programs[tp.prog]
	if prog == nil {
		return nil, false
	}
	l, err := link.Tracepoint(tp.category, tp.event, prog, nil)
	if err != nil {
		sym := tp.category + ":" + tp.event
		reportAttachFailure(tp.prog, sym, false, err)
		if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
			if tp.failMsg != "" {
				logger.Info(tp.failMsg, zap.Error(err))
			} else {
				logger.Debug("tracepoint unavailable", zap.String("tracepoint", sym), zap.Error(err))
			}
		}
		return nil, false
	}
	return l, true
}

// AttachProbeGroup attaches only the kprobes/tracepoints belonging to a
// single ProbeGroup. It is used for hot re-attach: SetEnabledCategories
// calls it when a CR newly needs a category whose group was previously
// detached.
func AttachProbeGroup(coll *ebpf.Collection, target ProbeGroup) ([]link.Link, error) {
	var links []link.Link
	rollback := func() {
		for _, l := range links {
			_ = l.Close()
		}
	}

	for progName, symbol := range mandatoryProbes {
		if GroupForProbe(progName) != target {
			continue
		}
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}
		l, err := attachKprobe(progName, symbol, prog)
		if err != nil {
			reportAttachFailure(progName, symbol, true, err)
			rollback()
			return nil, fmt.Errorf("re-attach mandatory probe %q (%s): %w", progName, symbol, NewProbeAttachError(progName, err))
		}
		links = append(links, l)
	}

	for progName, symbol := range optionalProbes {
		if GroupForProbe(progName) != target {
			continue
		}
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}
		l, err := attachKprobe(progName, symbol, prog)
		if err != nil {
			logger.Debug("optional probe unavailable on re-attach",
				zap.String("prog", progName), zap.String("symbol", symbol), zap.Error(err))
			continue
		}
		links = append(links, l)
	}

	for _, tp := range tracepointProbes {
		if GroupForProbe(tp.prog) != target {
			continue
		}
		if l, ok := attachTracepointSpec(coll, tp); ok {
			links = append(links, l)
		}
	}

	return links, nil
}

func AttachDNSProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachDNSProbesWithPID(coll, containerID, 0)
}

// packetDNSCaptureEnabled reports whether the libc-independent, packet-based
// DNS capture path is active.
func packetDNSCaptureEnabled() bool {
	return os.Getenv("PODTRACE_DNS_PACKET_CAPTURE") != "false"
}

// AttachDNSPacketProbes attaches the cgroup_skb DNS program to each target pod
// cgroup, capturing DNS by parsing packets rather than via libc uprobes.
func AttachDNSPacketProbes(coll *ebpf.Collection, cgroupPaths []string) []link.Link {
	if !packetDNSCaptureEnabled() {
		logger.Debug("Packet-based DNS capture disabled via PODTRACE_DNS_PACKET_CAPTURE=false")
		return nil
	}
	egress := coll.Programs["dns_egress"]
	ingress := coll.Programs["dns_ingress"]
	if egress == nil && ingress == nil {
		return nil
	}
	attach := []struct {
		prog *ebpf.Program
		typ  ebpf.AttachType
		name string
	}{
		{egress, ebpf.AttachCGroupInetEgress, "egress"},
		{ingress, ebpf.AttachCGroupInetIngress, "ingress"},
	}

	var links []link.Link
	seen := make(map[string]struct{}, len(cgroupPaths))
	for _, path := range cgroupPaths {
		if path == "" {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		for _, a := range attach {
			if a.prog == nil {
				continue
			}
			l, err := link.AttachCgroup(link.CgroupOptions{
				Path:    path,
				Attach:  a.typ,
				Program: a.prog,
			})
			if err != nil {
				logger.Info("Packet-based DNS capture unavailable for cgroup; falling back to libc uprobe only",
					zap.String("cgroup", path), zap.String("direction", a.name), zap.Error(err))
				continue
			}
			links = append(links, l)
		}
	}
	if len(links) > 0 {
		logger.Info("Packet-based DNS capture attached",
			zap.Int("cgroups", len(seen)), zap.Int("links", len(links)))
	} else {
		logger.Info("Packet-based DNS capture attached to no cgroups",
			zap.Int("cgroup_paths_given", len(cgroupPaths)))
	}
	return links
}

func AttachDNSProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	var links []link.Link
	libcPath := FindLibcPathWithPID(containerID, pid)
	if libcPath != "" {
		uprobe, err := link.OpenExecutable(libcPath)
		if err == nil {
			if uprobeProg := coll.Programs["uprobe_getaddrinfo"]; uprobeProg != nil {
				l, err := uprobe.Uprobe("getaddrinfo", uprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else {
					logger.Info("DNS tracking (uprobe) unavailable", zap.Error(err))
				}
			}
			if uretprobeProg := coll.Programs["uretprobe_getaddrinfo"]; uretprobeProg != nil {
				l, err := uprobe.Uretprobe("getaddrinfo", uretprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else {
					logger.Info("DNS tracking (uretprobe) unavailable", zap.Error(err))
				}
			}
		} else if packetDNSCaptureEnabled() {
			logger.Debug("libc uprobe DNS unavailable; DNS is captured via the packet-based path instead")
		} else {
			logger.Info("DNS tracking disabled: libc was located but could not be opened for uprobe attachment. DNS name resolution will not be traced; other tracing is unaffected.")
		}
	} else if packetDNSCaptureEnabled() {
		logger.Debug("libc uprobe DNS unavailable; DNS is captured via the packet-based path instead")
	} else {
		logger.Info("DNS tracking disabled: no libc found in the target container and packet-based DNS capture is disabled. DNS name resolution will not be traced; other tracing is unaffected.")
	}
	return links
}

func AttachSyncProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachSyncProbesWithPID(coll, containerID, 0)
}

func AttachSyncProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	var links []link.Link
	libcPath := FindLibcPathWithPID(containerID, pid)
	if libcPath == "" {
		return links
	}
	uprobe, err := link.OpenExecutable(libcPath)
	if err != nil {
		logger.Info("Lock tracking unavailable", zap.Error(err))
		return links
	}
	if prog := coll.Programs["uprobe_pthread_mutex_lock"]; prog != nil {
		l, err := uprobe.Uprobe("pthread_mutex_lock", prog, nil)
		if err == nil {
			links = append(links, l)
		} else if !strings.Contains(err.Error(), "symbol pthread_mutex_lock not found") {
			logger.Info("Pthread mutex lock tracking unavailable", zap.Error(err))
		}
	}
	if prog := coll.Programs["uretprobe_pthread_mutex_lock"]; prog != nil {
		l, err := uprobe.Uretprobe("pthread_mutex_lock", prog, nil)
		if err == nil {
			links = append(links, l)
		} else if !strings.Contains(err.Error(), "symbol pthread_mutex_lock not found") {
			logger.Info("Pthread mutex lock tracking unavailable", zap.Error(err))
		}
	}
	return links
}

func AttachDBProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachDBProbesWithPID(coll, containerID, 0)
}

func AttachDBProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	var links []link.Link

	libpqPaths := findDBLibsWithPID(containerID, pid, []string{"libpq.so.5", "libpq.so"})
	for _, path := range libpqPaths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			continue
		}
		if prog := coll.Programs["uprobe_PQexec"]; prog != nil {
			l, err := exe.Uprobe("PQexec", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
		if prog := coll.Programs["uretprobe_PQexec"]; prog != nil {
			l, err := exe.Uretprobe("PQexec", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
	}

	mysqlPaths := findDBLibsWithPID(containerID, pid, []string{"libmysqlclient.so.21", "libmysqlclient.so"})
	for _, path := range mysqlPaths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			continue
		}
		if prog := coll.Programs["uprobe_mysql_real_query"]; prog != nil {
			l, err := exe.Uprobe("mysql_real_query", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
		if prog := coll.Programs["uretprobe_mysql_real_query"]; prog != nil {
			l, err := exe.Uretprobe("mysql_real_query", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
	}

	return links
}

type dbProbeConfig struct {
	name           string
	libPatterns    []string
	acquireSymbols []string
	releaseSymbol  string
	exhaustSymbol  string
	acquireProg    string
	releaseProg    string
	exhaustProg    string
	exhaustRetProg string
}

func AttachPoolProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachPoolProbesWithPID(coll, containerID, 0)
}

func AttachPoolProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	var links []link.Link

	var binaryPaths []string
	if pid == 0 && containerID != "" {
		pid = findContainerProcess(containerID)
	}
	if pid > 0 {
		logger.Debug("Found container process", zap.Uint32("pid", pid), zap.String("containerID", containerID))

		binaryPath := findGoBinaryViaProcessMaps(pid)
		if binaryPath == "" {
			binaryPath = findGoBinaryInProcess(pid)
		}
		if binaryPath == "" {
			binaryPath = findGoBinaryInContainer(containerID, pid)
		}

		if binaryPath != "" {
			binaryPaths = append(binaryPaths, binaryPath)
			logger.Debug("Found Go binary for pool monitoring", zap.String("path", binaryPath), zap.Uint32("pid", pid))
		} else {
			logger.Debug("Go binary not found for process", zap.Uint32("pid", pid))
		}
	} else {
		logger.Debug("Container process not found", zap.String("containerID", containerID))
	}

	dbConfigs := []dbProbeConfig{
		{
			name:           "sqlite",
			libPatterns:    []string{"libsqlite3.so.0", "libsqlite3.so", "sqlite3.so"},
			acquireSymbols: []string{"sqlite3_prepare_v2", "sqlite3_prepare", "sqlite3_prepare16", "sqlite3_prepare16_v2"},
			releaseSymbol:  "sqlite3_finalize",
			exhaustSymbol:  "sqlite3_step",
			acquireProg:    "uprobe_sqlite3_prepare_v2",
			releaseProg:    "uretprobe_sqlite3_finalize",
			exhaustProg:    "uprobe_sqlite3_step",
			exhaustRetProg: "uretprobe_sqlite3_step",
		},
		{
			name:           "postgresql",
			libPatterns:    []string{"libpq.so.5", "libpq.so"},
			acquireSymbols: []string{"PQconnectStart"},
			releaseSymbol:  "PQfinish",
			exhaustSymbol:  "PQexec",
			acquireProg:    "uprobe_PQconnectStart",
			releaseProg:    "uretprobe_PQfinish",
			exhaustProg:    "uprobe_PQexec_pool",
			exhaustRetProg: "",
		},
		{
			name:           "mysql",
			libPatterns:    []string{"libmysqlclient.so.21", "libmysqlclient.so"},
			acquireSymbols: []string{"mysql_real_connect"},
			releaseSymbol:  "mysql_close",
			exhaustSymbol:  "mysql_real_query",
			acquireProg:    "uprobe_mysql_real_connect",
			releaseProg:    "uretprobe_mysql_close",
			exhaustProg:    "uprobe_mysql_real_query_pool",
			exhaustRetProg: "",
		},
	}

	for _, dbConfig := range dbConfigs {
		var dbPaths []string
		dbPaths = append(dbPaths, binaryPaths...)
		libPaths := findDBLibsWithPID(containerID, pid, dbConfig.libPatterns)
		dbPaths = append(dbPaths, libPaths...)

		if len(dbPaths) == 0 {
			logger.Debug("No libraries found for database", zap.String("database", dbConfig.name), zap.String("containerID", containerID))
			continue
		}

		for _, path := range dbPaths {
			logger.Debug("Attaching pool probes", zap.String("database", dbConfig.name), zap.String("path", path))
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			exe, err := link.OpenExecutable(path)
			if err != nil {
				logger.Debug("Failed to open executable for pool probes", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
				continue
			}

			for _, symbol := range dbConfig.acquireSymbols {
				if prog := coll.Programs[dbConfig.acquireProg]; prog != nil {
					l, err := exe.Uprobe(symbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool acquire probe", zap.String("database", dbConfig.name), zap.String("symbol", symbol), zap.String("path", path))
						break
					}
				}
			}

			if dbConfig.releaseProg != "" && dbConfig.releaseSymbol != "" {
				if prog := coll.Programs[dbConfig.releaseProg]; prog != nil {
					l, err := exe.Uretprobe(dbConfig.releaseSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool release probe", zap.String("database", dbConfig.name), zap.String("path", path))
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.releaseSymbol)) {
						logger.Debug("Pool release probe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}

			if dbConfig.exhaustProg != "" && dbConfig.exhaustSymbol != "" {
				if prog := coll.Programs[dbConfig.exhaustProg]; prog != nil {
					l, err := exe.Uprobe(dbConfig.exhaustSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool exhaustion probe", zap.String("database", dbConfig.name), zap.String("path", path))
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.exhaustSymbol)) {
						logger.Debug("Pool exhaustion probe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}

			if dbConfig.exhaustRetProg != "" && dbConfig.exhaustSymbol != "" {
				if prog := coll.Programs[dbConfig.exhaustRetProg]; prog != nil {
					l, err := exe.Uretprobe(dbConfig.exhaustSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.exhaustSymbol)) {
						logger.Debug("Pool exhaustion retprobe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}
		}
	}

	if len(links) > 0 {
		logger.Debug("Pool monitoring probes attached", zap.Int("total_links", len(links)), zap.String("containerID", containerID))
	} else {
		logger.Debug("No pool monitoring probes attached", zap.String("containerID", containerID))
	}

	return links
}

func FindLibcPath(containerID string) string {
	if containerID != "" {
		if path := findLibcInContainer(containerID); path != "" {
			return path
		}
	}

	if path := findLibcViaLdconfig(); path != "" {
		return path
	}

	if path := findLibcViaLdSoConf(); path != "" {
		return path
	}

	return findLibcViaCommonPaths()
}

func FindLibcPathWithPID(containerID string, pid uint32) string {
	if pid > 0 {
		if path := findLibcViaProcessMapsProcRoot(pid); path != "" {
			return path
		}
		if path := findLibcInProcess(pid); path != "" {
			return path
		}
	}
	return FindLibcPath(containerID)
}

func findLibcViaLdconfig() string {
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libc.so.6") || strings.Contains(line, "libc.musl") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "=>" && i+1 < len(parts) {
					path := strings.TrimSpace(parts[i+1])
					if info, err := os.Stat(path); err == nil && !info.IsDir() {
						return path
					}
				}
			}
		}
	}
	return ""
}

func getMuslLibcNames() []string {
	names := []string{"libc.so.6"}
	arch := runtime.GOARCH

	muslArchMap := map[string]string{
		"amd64":   "x86_64",
		"arm64":   "aarch64",
		"riscv64": "riscv64",
		"ppc64le": "ppc64le",
		"s390x":   "s390x",
	}

	if muslArch, ok := muslArchMap[arch]; ok {
		names = append(names, fmt.Sprintf("libc.musl-%s.so.1", muslArch))
	}

	return names
}

func findLibcViaLdSoConf() string {
	searchPaths := append(config.GetDefaultLibSearchPaths(), ldsoconf.SearchPaths()...)

	libcNames := getMuslLibcNames()
	for _, searchPath := range searchPaths {
		for _, libcName := range libcNames {
			path := filepath.Join(searchPath, libcName)
			if hostfs.IsRegularFile(path) {
				return path
			}
		}
	}
	return ""
}

func findLibcViaProcessMaps(pid uint32) string {
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "libc.so") || strings.Contains(line, "libc.musl") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				path := parts[5]
				if hostfs.IsRegularFile(path) {
					return path
				}
			}
		}
	}
	return ""
}

func findLibcViaProcessMapsProcRoot(pid uint32) string {
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "libc.so") || strings.Contains(line, "libc.musl") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				containerPath := parts[5]
				if path := fileInProcRoot(pid, containerPath); path != "" {
					return path
				}
			}
		}
	}
	return ""
}

func findLibcInProcess(pid uint32) string {
	procRootPaths := getArchitecturePaths()
	for _, basePath := range procRootPaths {
		path := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root", basePath)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func fileInProcRoot(pid uint32, containerPath string) string {
	if containerPath == "" || strings.HasPrefix(containerPath, "[") {
		return ""
	}
	procRoot := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")
	hostPath := filepath.Join(procRoot, strings.TrimPrefix(containerPath, "/"))
	if hostfs.IsRegularFile(hostPath) {
		return hostPath
	}
	if hostfs.IsRegularFile(containerPath) {
		return containerPath
	}
	return ""
}

func findContainerProcess(containerID string) uint32 {
	entries, err := os.ReadDir(config.ProcBasePath)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		if data, err := procfs.ReadFile(pidStr + "/cgroup"); err == nil {
			if strings.Contains(string(data), containerID) {
				var pid uint32
				if _, err := fmt.Sscanf(pidStr, "%d", &pid); err == nil {
					return pid
				}
			}
		}
	}
	return 0
}

func findGoBinaryInProcess(pid uint32) string {
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		logger.Debug("Failed to read exe symlink", zap.Uint32("pid", pid), zap.String("path", exePath), zap.Error(err))
		return ""
	}

	if !filepath.IsAbs(target) {
		cwdPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "cwd")
		cwd, err := os.Readlink(cwdPath)
		if err != nil {
			logger.Debug("Failed to read cwd symlink", zap.Uint32("pid", pid), zap.Error(err))
			cwd = "/"
		}
		target = filepath.Join(cwd, target)
	}

	procRootPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")
	hostPath := filepath.Join(procRootPath, strings.TrimPrefix(target, "/"))

	if info, err := os.Stat(hostPath); err == nil && !info.IsDir() {
		logger.Debug("Found binary via container root", zap.Uint32("pid", pid), zap.String("container_path", target), zap.String("host_path", hostPath))
		return hostPath
	}

	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		logger.Debug("Found binary via direct path", zap.Uint32("pid", pid), zap.String("path", target))
		return target
	}

	logger.Debug("Binary not found or not accessible", zap.Uint32("pid", pid), zap.String("target", target), zap.String("host_path", hostPath), zap.Error(err))
	return ""
}

func findGoBinaryViaProcessMaps(pid uint32) string {
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		logger.Debug("Failed to read process maps", zap.Uint32("pid", pid), zap.Error(err))
		return ""
	}

	procRootPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "r-xp") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				binaryPath := parts[5]
				if binaryPath != "" && !strings.HasPrefix(binaryPath, "[") {
					if strings.Contains(binaryPath, ".so") || strings.Contains(binaryPath, "vdso") || strings.Contains(binaryPath, "vsyscall") {
						continue
					}

					hostPath := filepath.Join(procRootPath, strings.TrimPrefix(binaryPath, "/"))
					if hostfs.IsRegularFile(hostPath) {
						logger.Debug("Found binary via process maps", zap.Uint32("pid", pid), zap.String("container_path", binaryPath), zap.String("host_path", hostPath))
						return hostPath
					}

					if hostfs.IsRegularFile(binaryPath) {
						logger.Debug("Found binary via process maps (direct)", zap.Uint32("pid", pid), zap.String("path", binaryPath))
						return binaryPath
					}
				}
			}
		}
	}
	return ""
}

func findGoBinaryInContainer(containerID string, pid uint32) string {
	procRootPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")

	if cmdlineData, err := procfs.ReadFile(fmt.Sprintf("%d/cmdline", pid)); err == nil {
		cmdline := string(cmdlineData)
		if len(cmdline) > 0 {
			parts := strings.Split(cmdline, "\x00")
			if len(parts) > 0 && parts[0] != "" {
				binaryPath := parts[0]
				if filepath.IsAbs(binaryPath) {
					hostPath := filepath.Join(procRootPath, strings.TrimPrefix(binaryPath, "/"))
					if hostfs.IsRegularFile(hostPath) {
						logger.Debug("Found binary via cmdline", zap.Uint32("pid", pid), zap.String("cmdline_path", binaryPath), zap.String("host_path", hostPath))
						return hostPath
					}
				}
			}
		}
	}

	if commData, err := procfs.ReadFile(fmt.Sprintf("%d/comm", pid)); err == nil {
		commName := strings.TrimSpace(string(commData))
		if commName != "" {
			commonPaths := []string{
				filepath.Join("/app", commName),
				filepath.Join("/app", commName+".app"),
				filepath.Join("/usr/local/bin", commName),
				filepath.Join("/bin", commName),
				filepath.Join("/app", "main"),
				filepath.Join("/app", "app"),
			}
			for _, relPath := range commonPaths {
				hostPath := filepath.Join(procRootPath, strings.TrimPrefix(relPath, "/"))
				if hostfs.IsRegularFile(hostPath) {
					logger.Debug("Found binary via comm name", zap.Uint32("pid", pid), zap.String("comm", commName), zap.String("path", hostPath))
					return hostPath
				}
			}
		}
	}

	commonPaths := config.GetCommonBinarySearchPaths()

	for _, relPath := range commonPaths {
		hostPath := filepath.Join(procRootPath, strings.TrimPrefix(relPath, "/"))
		if info, err := os.Stat(hostPath); err == nil && !info.IsDir() {
			logger.Debug("Found binary via container root common paths", zap.Uint32("pid", pid), zap.String("path", hostPath))
			return hostPath
		}
	}

	rootfsPaths := []string{}
	if dockerRootfs, err := config.GetDockerContainerRootfs(containerID); err == nil {
		rootfsPaths = append(rootfsPaths, dockerRootfs)
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	commonPathsForRootfs := config.GetCommonBinarySearchPaths()
	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			for _, relPath := range commonPathsForRootfs {
				path := filepath.Join(rootfs, strings.TrimPrefix(relPath, "/"))
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					logger.Debug("Found binary via container rootfs", zap.String("rootfs", rootfs), zap.String("path", path))
					return path
				}
			}
		}
	}

	return ""
}

func findLibcInContainer(containerID string) string {
	if pid := findContainerProcess(containerID); pid > 0 {
		if path := findLibcViaProcessMaps(pid); path != "" {
			return path
		}

		procRootPaths := getArchitecturePaths()
		for _, basePath := range procRootPaths {
			path := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root", basePath)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path
			}
		}
	}

	rootfsPaths := []string{}
	if dockerRootfs, err := config.GetDockerContainerRootfs(containerID); err == nil {
		rootfsPaths = append(rootfsPaths, dockerRootfs)
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			libcPaths := getArchitecturePaths()
			for _, libcPath := range libcPaths {
				path := filepath.Join(rootfs, libcPath)
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path
				}
			}
		}
	}

	procPaths := getArchitecturePaths()
	for _, basePath := range procPaths {
		path := filepath.Join(config.GetDefaultProcRootPath(), basePath)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}

	return ""
}

func getArchitecturePaths() []string {
	arch := runtime.GOARCH
	paths := []string{}

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			paths = append(paths,
				fmt.Sprintf("lib/%s/libc.so.6", suffix),
				fmt.Sprintf("usr/lib/%s/libc.so.6", suffix),
			)
		}
	}

	paths = append(paths,
		"lib64/libc.so.6",
		"lib/libc.so.6",
		"usr/lib64/libc.so.6",
		"usr/lib/libc.so.6",
	)

	return paths
}

func findLibcViaCommonPaths() string {
	paths := getArchitecturePaths()
	for _, relPath := range paths {
		path := filepath.Join("/", relPath)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func findDBLibsViaLdconfig(libNames []string) []string {
	var paths []string
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return paths
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		for _, libName := range libNames {
			if strings.Contains(line, libName) {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "=>" && i+1 < len(parts) {
						path := strings.TrimSpace(parts[i+1])
						if info, err := os.Stat(path); err == nil && !info.IsDir() {
							paths = append(paths, path)
						}
					}
				}
			}
		}
	}
	return paths
}

func findDBLibsViaLdSoConf(libNames []string) []string {
	var paths []string
	searchPaths := append(config.GetDefaultLibSearchPaths(), ldsoconf.SearchPaths()...)

	for _, searchPath := range searchPaths {
		for _, libName := range libNames {
			path := filepath.Join(searchPath, libName)
			if hostfs.IsRegularFile(path) {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func getArchitectureDBPaths(libNames []string) []string {
	var paths []string
	arch := runtime.GOARCH

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			for _, libName := range libNames {
				paths = append(paths,
					fmt.Sprintf("/usr/lib/%s/%s", suffix, libName),
					fmt.Sprintf("/lib/%s/%s", suffix, libName),
				)
			}
		}
	}

	for _, libName := range libNames {
		paths = append(paths,
			fmt.Sprintf("/usr/lib64/%s", libName),
			fmt.Sprintf("/usr/lib/%s", libName),
			fmt.Sprintf("/lib64/%s", libName),
			fmt.Sprintf("/lib/%s", libName),
		)
	}

	return paths
}

func findDBLibsViaProcessMaps(pid uint32, libNames []string) []string {
	var paths []string
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return paths
	}

	for _, line := range strings.Split(string(data), "\n") {
		for _, libName := range libNames {
			if strings.Contains(line, libName) {
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					path := parts[5]
					if hostfs.IsRegularFile(path) {
						paths = append(paths, path)
					}
				}
			}
		}
	}
	return paths
}

func findDBLibsViaProcessMapsProcRoot(pid uint32, libNames []string) []string {
	var paths []string
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return paths
	}

	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		for _, libName := range libNames {
			if strings.Contains(line, libName) {
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					containerPath := parts[5]
					if hostPath := fileInProcRoot(pid, containerPath); hostPath != "" && !seen[hostPath] {
						paths = append(paths, hostPath)
						seen[hostPath] = true
					}
				}
			}
		}
	}
	return paths
}

func findDBLibsInContainer(containerID string, libNames []string) []string {
	var paths []string

	if pid := findContainerProcess(containerID); pid > 0 {
		if foundPaths := findDBLibsViaProcessMaps(pid, libNames); len(foundPaths) > 0 {
			paths = append(paths, foundPaths...)
		}

		archPaths := getArchitectureDBPaths(libNames)
		for _, basePath := range archPaths {
			path := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root", strings.TrimPrefix(basePath, "/"))
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
			}
		}
	}

	rootfsPaths := []string{}
	if dockerRootfs, err := config.GetDockerContainerRootfs(containerID); err == nil {
		rootfsPaths = append(rootfsPaths, dockerRootfs)
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			archPaths := getArchitectureDBPaths(libNames)
			for _, basePath := range archPaths {
				path := filepath.Join(rootfs, strings.TrimPrefix(basePath, "/"))
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					paths = append(paths, path)
				}
			}
		}
	}

	archPaths := getArchitectureDBPaths(libNames)
	for _, basePath := range archPaths {
		path := filepath.Join(config.GetDefaultProcRootPath(), strings.TrimPrefix(basePath, "/"))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
	}

	return paths
}

func findDBLibsWithPID(containerID string, pid uint32, libNames []string) []string {
	if pid > 0 {
		var out []string
		seen := make(map[string]bool)

		for _, p := range findDBLibsViaProcessMapsProcRoot(pid, libNames) {
			if !seen[p] {
				out = append(out, p)
				seen[p] = true
			}
		}

		archPaths := getArchitectureDBPaths(libNames)
		for _, basePath := range archPaths {
			p := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root", strings.TrimPrefix(basePath, "/"))
			if info, err := os.Stat(p); err == nil && !info.IsDir() && !seen[p] {
				out = append(out, p)
				seen[p] = true
			}
		}

		if len(out) > 0 {
			return out
		}
	}
	return findDBLibs(containerID, libNames)
}

func findDBLibs(containerID string, libNames []string) []string {
	var paths []string
	seen := make(map[string]bool)

	if containerID != "" {
		containerPaths := findDBLibsInContainer(containerID, libNames)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	ldconfigPaths := findDBLibsViaLdconfig(libNames)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findDBLibsViaLdSoConf(libNames)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	commonPaths := getArchitectureDBPaths(libNames)
	for _, path := range commonPaths {
		if !seen[path] {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	return paths
}

func FindLibcInContainer(containerID string) []string {
	paths := []string{}
	containerRoot, err := config.GetDockerContainerRootfs(containerID)
	if err != nil {
		return paths
	}
	if _, err := os.Stat(containerRoot); err == nil {
		libcPaths := getArchitecturePaths()
		for _, libcPath := range libcPaths {
			paths = append(paths, filepath.Join(containerRoot, libcPath))
		}
	}

	procPaths := getArchitecturePaths()
	for _, basePath := range procPaths {
		paths = append(paths, filepath.Join(config.GetDefaultProcRootPath(), basePath))
	}

	return paths
}

func findTLSLibsViaProcessMaps(pid uint32, libPatterns []string) []string {
	var paths []string
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return paths
	}

	for _, line := range strings.Split(string(data), "\n") {
		for _, pattern := range libPatterns {
			if strings.Contains(line, pattern) {
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					path := parts[5]
					if hostfs.IsRegularFile(path) {
						paths = append(paths, path)
					}
				}
			}
		}
	}
	return paths
}

func findTLSLibsViaProcessMapsProcRoot(pid uint32, libPatterns []string) []string {
	var paths []string
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return paths
	}

	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		for _, pattern := range libPatterns {
			if strings.Contains(line, pattern) {
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					containerPath := parts[5]
					if hostPath := fileInProcRoot(pid, containerPath); hostPath != "" && !seen[hostPath] {
						paths = append(paths, hostPath)
						seen[hostPath] = true
					}
				}
			}
		}
	}
	return paths
}

func findTLSLibsInContainer(containerID string, libPatterns []string) []string {
	var paths []string

	if pid := findContainerProcess(containerID); pid > 0 {
		if foundPaths := findTLSLibsViaProcessMaps(pid, libPatterns); len(foundPaths) > 0 {
			paths = append(paths, foundPaths...)
		}
	}

	rootfsPaths := []string{}
	if dockerRootfs, err := config.GetDockerContainerRootfs(containerID); err == nil {
		rootfsPaths = append(rootfsPaths, dockerRootfs)
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			archPaths := getArchitectureDBPaths(libPatterns)
			for _, basePath := range archPaths {
				path := filepath.Join(rootfs, strings.TrimPrefix(basePath, "/"))
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					paths = append(paths, path)
				}
			}
			if err := filepath.Walk(rootfs, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				baseName := strings.ToLower(filepath.Base(path))
				for _, pattern := range libPatternsLower {
					if strings.Contains(baseName, pattern) {
						paths = append(paths, path)
						return nil
					}
				}
				return nil
			}); err != nil {
				continue
			}
		}
	}

	return paths
}

func findTLSLibsInContainerWithPID(containerID string, pid uint32, libPatterns []string) []string {
	if pid > 0 {
		if foundPaths := findTLSLibsViaProcessMapsProcRoot(pid, libPatterns); len(foundPaths) > 0 {
			return foundPaths
		}
		if foundPaths := findTLSLibsViaProcRootScan(pid, libPatterns); len(foundPaths) > 0 {
			return foundPaths
		}
	}
	return findTLSLibsInContainer(containerID, libPatterns)
}

// findTLSLibsViaProcRootScan walks the container rootfs (via /proc/<pid>/root)
// looking for shared-library files whose name matches one of libPatterns,
// independent of whether the resolved process has them mapped. Symlinks are
// resolved and de-duplicated so a uprobe is not attached twice to the same
// underlying file.
func findTLSLibsViaProcRootScan(pid uint32, libPatterns []string) []string {
	root := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")
	dirs := append(config.GetDefaultLibSearchPaths(),
		"/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu",
		"/usr/lib/aarch64-linux-gnu", "/lib/aarch64-linux-gnu",
	)
	patternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		patternsLower[i] = strings.ToLower(p)
	}
	var paths []string
	seen := make(map[string]bool)
	for _, d := range dirs {
		dirPath := filepath.Join(root, strings.TrimPrefix(d, "/"))
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Debug("TLS rootfs scan: readdir failed", zap.String("dir", dirPath), zap.Error(err))
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
				continue
			}
			nameLower := strings.ToLower(e.Name())
			if !strings.Contains(nameLower, ".so") {
				continue
			}
			matched := false
			for _, pat := range patternsLower {
				if strings.Contains(nameLower, pat) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			full := filepath.Join(dirPath, e.Name())
			if seen[full] {
				continue
			}
			seen[full] = true
			paths = append(paths, full)
		}
	}
	logger.Debug("TLS rootfs scan complete", zap.Uint32("pid", pid), zap.String("root", root), zap.Int("found", len(paths)))
	return paths
}

func findTLSLibsViaLdconfig(libPatterns []string) []string {
	var paths []string
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return paths
	}

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		for _, pattern := range libPatternsLower {
			if strings.Contains(lineLower, pattern) {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "=>" && i+1 < len(parts) {
						path := strings.TrimSpace(parts[i+1])
						if info, err := os.Stat(path); err == nil && !info.IsDir() {
							paths = append(paths, path)
						}
					}
				}
			}
		}
	}
	return paths
}

func findTLSLibsViaLdSoConf(libPatterns []string) []string {
	var paths []string
	searchPaths := append(config.GetDefaultLibSearchPaths(), ldsoconf.SearchPaths()...)

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	for _, searchPath := range searchPaths {
		_ = hostfs.WalkRegular(searchPath, func(path string, info os.FileInfo) error {
			baseName := strings.ToLower(filepath.Base(path))
			for _, pattern := range libPatternsLower {
				if strings.Contains(baseName, pattern) {
					paths = append(paths, path)
					return nil
				}
			}
			return nil
		})
	}
	return paths
}

func findTLSLibs(containerID string) []string {
	var paths []string
	seen := make(map[string]bool)

	libPatterns := []string{"libssl", "libgnutls", "libnss", "libmbedtls", "libmbedx509", "ssl"}

	if containerID != "" {
		containerPaths := findTLSLibsInContainer(containerID, libPatterns)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	ldconfigPaths := findTLSLibsViaLdconfig(libPatterns)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findTLSLibsViaLdSoConf(libPatterns)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	archPaths := getArchitectureTLSPaths(libPatterns)
	for _, path := range archPaths {
		if !seen[path] {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	commonLibPaths := []string{
		"/usr/lib64",
		"/usr/lib",
		"/lib64",
		"/lib",
		"/usr/local/lib64",
		"/usr/local/lib",
	}

	for _, libPath := range commonLibPaths {
		if _, err := os.Stat(libPath); err != nil {
			continue
		}
		err := filepath.Walk(libPath, func(walkPath string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			baseName := strings.ToLower(filepath.Base(walkPath))
			for _, pattern := range libPatterns {
				if strings.Contains(baseName, strings.ToLower(pattern)) {
					if !seen[walkPath] {
						paths = append(paths, walkPath)
						seen[walkPath] = true
					}
				}
			}
			return nil
		})
		if err != nil {
			continue
		}
	}

	return paths
}

func findTLSLibsWithPID(containerID string, pid uint32) []string {
	var paths []string
	seen := make(map[string]bool)

	libPatterns := []string{"libssl", "libgnutls", "libnss", "libmbedtls", "libmbedx509", "ssl"}

	if containerID != "" || pid > 0 {
		containerPaths := findTLSLibsInContainerWithPID(containerID, pid, libPatterns)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	ldconfigPaths := findTLSLibsViaLdconfig(libPatterns)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findTLSLibsViaLdSoConf(libPatterns)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	archPaths := getArchitectureTLSPaths(libPatterns)
	for _, path := range archPaths {
		if !seen[path] {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	return paths
}

func getArchitectureTLSPaths(libPatterns []string) []string {
	var paths []string
	arch := runtime.GOARCH

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
		"arm":     {"arm-linux-gnueabihf", "arm-linux-gnueabi"},
		"386":     {"i386-linux-gnu", "i686-linux-gnu"},
		"mips":    {"mips-linux-gnu", "mipsel-linux-gnu"},
		"mips64":  {"mips64-linux-gnuabi64", "mips64el-linux-gnuabi64"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			basePaths := []string{
				fmt.Sprintf("/usr/lib/%s", suffix),
				fmt.Sprintf("/lib/%s", suffix),
			}
			for _, basePath := range basePaths {
				if _, err := os.Stat(basePath); err == nil {
					for _, pattern := range libPatterns {
						err := filepath.Walk(basePath, func(walkPath string, info os.FileInfo, err error) error {
							if err != nil || info.IsDir() {
								return nil
							}
							baseName := strings.ToLower(filepath.Base(walkPath))
							if strings.Contains(baseName, strings.ToLower(pattern)) {
								paths = append(paths, walkPath)
							}
							return nil
						})
						if err != nil {
							continue
						}
					}
				}
			}
		}
	}

	commonPaths := []string{
		"/usr/lib64",
		"/usr/lib",
		"/lib64",
		"/lib",
	}

	for _, basePath := range commonPaths {
		if _, err := os.Stat(basePath); err == nil {
			for _, pattern := range libPatterns {
				err := filepath.Walk(basePath, func(walkPath string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return nil
					}
					baseName := strings.ToLower(filepath.Base(walkPath))
					if strings.Contains(baseName, strings.ToLower(pattern)) {
						paths = append(paths, walkPath)
					}
					return nil
				})
				if err != nil {
					continue
				}
			}
		}
	}

	return paths
}

func AttachTLSProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachTLSProbesWithPID(coll, containerID, 0)
}

func AttachTLSProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	links := []link.Link{}

	tlsLibPaths := findTLSLibsWithPID(containerID, pid)
	tlsSymbols := map[string][]string{
		"SSL_connect":           {"uprobe_SSL_connect", "uretprobe_SSL_connect"},
		"SSL_accept":            {"uprobe_SSL_accept", "uretprobe_SSL_accept"},
		"SSL_do_handshake":      {"uprobe_SSL_do_handshake", "uretprobe_SSL_do_handshake"},
		"gnutls_handshake":      {"uprobe_gnutls_handshake", "uretprobe_gnutls_handshake"},
		"mbedtls_ssl_handshake": {"uprobe_mbedtls_ssl_handshake", "uretprobe_mbedtls_ssl_handshake"},
		"SSL_write":             {"uprobe_SSL_write", ""},
		"SSL_read":              {"uprobe_SSL_read", "uretprobe_SSL_read"},
		"gnutls_record_send":    {"uprobe_gnutls_record_send", ""},
		"gnutls_record_recv":    {"uprobe_gnutls_record_recv", "uretprobe_gnutls_record_recv"},
	}

	logger.Debug("TLS probe attach: candidate libraries",
		zap.Strings("libs", tlsLibPaths), zap.String("containerID", containerID), zap.Uint32("pid", pid))

	for _, libPath := range tlsLibPaths {
		info, err := os.Stat(libPath)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(libPath)
		if err != nil {
			logger.Debug("TLS probe: cannot open library", zap.String("lib", libPath), zap.Error(err))
			continue
		}

		for symbol, progNames := range tlsSymbols {
			if len(progNames) < 2 {
				continue
			}
			uprobeProg := coll.Programs[progNames[0]]
			uretprobeProg := coll.Programs[progNames[1]]

			if uprobeProg != nil {
				l, err := exe.Uprobe(symbol, uprobeProg, nil)
				if err == nil {
					links = append(links, l)
					logger.Debug("TLS uprobe attached", zap.String("symbol", symbol), zap.String("lib", libPath))
				} else if !strings.Contains(err.Error(), "not found") {
					logger.Debug("TLS uprobe attach failed", zap.String("symbol", symbol), zap.String("lib", libPath), zap.Error(err))
				}
			}
			if uretprobeProg != nil {
				l, err := exe.Uretprobe(symbol, uretprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else if !strings.Contains(err.Error(), "not found") {
					logger.Debug("TLS uretprobe attach failed", zap.String("symbol", symbol), zap.String("lib", libPath), zap.Error(err))
				}
			}
		}
	}

	logger.Debug("TLS probe attach complete", zap.Int("links", len(links)))
	return links
}

// kernelVersionString returns the running kernel version for use in error messages.
func kernelVersionString() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	for i, f := range fields {
		if strings.EqualFold(f, "version") && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "unknown"
}
