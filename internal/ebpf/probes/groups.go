package probes

// ProbeGroup identifies a logical category of BPF probes that can be
// enabled or disabled at runtime via the management API.
type ProbeGroup string

const (
	GroupNetwork    ProbeGroup = "network"
	GroupFileSystem ProbeGroup = "filesystem"
	GroupDatabase   ProbeGroup = "database"
	GroupTLS        ProbeGroup = "tls"
	GroupMemory     ProbeGroup = "memory"
	GroupCPU        ProbeGroup = "cpu"
	GroupPool       ProbeGroup = "pool"
)

// probeGroupMap maps each BPF program name to its ProbeGroup.
// Programs absent from this map are treated as GroupNetwork by default.
var probeGroupMap = map[string]ProbeGroup{
	// Network
	"kprobe_tcp_connect":          GroupNetwork,
	"kretprobe_tcp_connect":       GroupNetwork,
	"kprobe_tcp_v6_connect":       GroupNetwork,
	"kretprobe_tcp_v6_connect":    GroupNetwork,
	"kprobe_tcp_sendmsg":          GroupNetwork,
	"kretprobe_tcp_sendmsg":       GroupNetwork,
	"kprobe_tcp_recvmsg":          GroupNetwork,
	"kretprobe_tcp_recvmsg":       GroupNetwork,
	"kprobe_udp_sendmsg":          GroupNetwork,
	"kretprobe_udp_sendmsg":       GroupNetwork,
	"kprobe_udp_recvmsg":          GroupNetwork,
	"kretprobe_udp_recvmsg":       GroupNetwork,
	"tracepoint_tcp_set_state":    GroupNetwork,
	"tracepoint_tcp_retransmit_skb": GroupNetwork,
	"tracepoint_net_dev_xmit":    GroupNetwork,

	// FileSystem
	"kprobe_vfs_write":          GroupFileSystem,
	"kretprobe_vfs_write":       GroupFileSystem,
	"kprobe_vfs_read":           GroupFileSystem,
	"kretprobe_vfs_read":        GroupFileSystem,
	"kprobe_vfs_fsync":          GroupFileSystem,
	"kretprobe_vfs_fsync":       GroupFileSystem,
	"kprobe_do_sys_openat2":     GroupFileSystem,
	"kretprobe_do_sys_openat2":  GroupFileSystem,
	"kprobe_vfs_unlink":         GroupFileSystem,
	"kretprobe_vfs_unlink":      GroupFileSystem,
	"kprobe_vfs_rename":         GroupFileSystem,
	"kretprobe_vfs_rename":      GroupFileSystem,

	// CPU
	"tracepoint_sched_switch":       GroupCPU,
	"kprobe_do_futex":               GroupCPU,
	"kretprobe_do_futex":            GroupCPU,

	// Memory
	"tracepoint_page_fault_user":  GroupMemory,
	"tracepoint_oom_kill_process": GroupMemory,

	// Process (grouped under CPU for simplicity)
	"tracepoint_sched_process_fork": GroupCPU,

	// TLS (uprobes attached separately via SetContainerID)
	"uprobe_getaddrinfo":              GroupTLS,
	"uretprobe_getaddrinfo":           GroupTLS,
	"uprobe_pthread_mutex_lock":       GroupTLS,
	"uretprobe_pthread_mutex_lock":    GroupTLS,

	// Database
	"uprobe_PQexec":   GroupDatabase,
	"uretprobe_PQexec": GroupDatabase,

	// Pool
	"uprobe_pool_acquire":  GroupPool,
	"uretprobe_pool_acquire": GroupPool,
}

// GroupForProbe returns the ProbeGroup for a BPF program name.
func GroupForProbe(progName string) ProbeGroup {
	if g, ok := probeGroupMap[progName]; ok {
		return g
	}
	return GroupNetwork
}
