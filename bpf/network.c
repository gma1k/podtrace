// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF
static __noinline void stash_tcp_peer(struct pt_regs *ctx, u32 pair)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return;
	u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (dport_be == 0)
		return;
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	char buf[MAX_STRING_LEN] = {};
	if (family == AF_INET) {
		u32 daddr_be = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		if (daddr_be == 0)
			return;
		format_ip_port(__builtin_bswap32(daddr_be), __builtin_bswap16(dport_be), buf);
	} else if (family == AF_INET6) {
		u8 d6[16] = {};
		BPF_CORE_READ_INTO(&d6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		format_ipv6_port(d6, __builtin_bswap16(dport_be), buf);
	} else {
		return;
	}
	struct pair_key key = make_pair_key(pair);
	bpf_map_update_elem(&tcp_target, &key, buf, BPF_ANY);
}
#else
static __always_inline void stash_tcp_peer(struct pt_regs *ctx, u32 pair)
{
	(void)ctx;
	(void)pair;
}
#endif

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V4);
	record_start_time(&key);

	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		struct sockaddr_in sa;
		if (bpf_probe_read_kernel(&sa, sizeof(sa), uaddr) == 0 &&
		    sa.sin_family == AF_INET) {
			struct connect_addr ca = {};
			ca.family = AF_INET;
			ca.port_be = sa.sin_port;
			ca.addr_be = sa.sin_addr.s_addr;
			bpf_map_update_elem(&connect_addrs, &key, &ca, BPF_ANY);
		}
	}
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe_tcp_v6_connect(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V6);
	record_start_time(&key);

	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		struct {
			u16 sin6_family;
			u16 sin6_port;
			u32 sin6_flowinfo;
			u8  sin6_addr[16];
			u32 sin6_scope_id;
		} sa6;
		if (bpf_probe_read_kernel(&sa6, sizeof(sa6), uaddr) == 0 &&
		    sa6.sin6_family == AF_INET6) {
			struct connect_addr ca = {};
			ca.family = AF_INET6;
			ca.port_be = sa6.sin6_port;
			__builtin_memcpy(ca.addr6, sa6.sin6_addr, 16);
			bpf_map_update_elem(&connect_addrs, &key, &ca, BPF_ANY);
		}
	}
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe_tcp_v6_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V6);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_CONNECT;
	e->latency_ns = calc_latency(*start_ts);
	e->error = PT_REGS_RC(ctx);
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	e->details[0] = '\0';

	struct connect_addr *ca = bpf_map_lookup_elem(&connect_addrs, &key);
	if (ca && ca->family == AF_INET6) {
		u16 port = __builtin_bswap16(ca->port_be);
		format_ipv6_port(ca->addr6, port, e->target);
		struct dns_v6key k6 = {};
		__builtin_memcpy(k6.addr, ca->addr6, 16);
		char *resolved = bpf_map_lookup_elem(&dns_resolved6, &k6);
		if (resolved) {
			__builtin_memcpy(e->details, resolved, MAX_STRING_LEN);
		}
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&connect_addrs, &key);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V4);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_CONNECT;
	e->latency_ns = calc_latency(*start_ts);
	e->error = PT_REGS_RC(ctx);
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	e->details[0] = '\0';

	struct connect_addr *ca = bpf_map_lookup_elem(&connect_addrs, &key);
	if (ca && ca->family == AF_INET) {
		u16 port = __builtin_bswap16(ca->port_be);
		u32 ip = __builtin_bswap32(ca->addr_be);
		format_ip_port(ip, port, e->target);
		u32 ip_be = ca->addr_be;
		char *resolved = bpf_map_lookup_elem(&dns_resolved, &ip_be);
		if (resolved) {
			__builtin_memcpy(e->details, resolved, MAX_STRING_LEN);
		}
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&connect_addrs, &key);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_SENDMSG);
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	stash_tcp_peer(ctx, PAIR_TCP_SENDMSG);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_SENDMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);

	if (!start_ts) {
		return 0;
	}

	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}

	u64 latency_ns = calc_latency(*start_ts);

	u64 conn_key = get_key(pid, tid);

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		bpf_map_delete_elem(&grpc_methods, &conn_key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TCP_SEND;
	e->latency_ns = latency_ns;
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;

	char *conn_ptr = bpf_map_lookup_elem(&socket_conns, &conn_key);
	if (conn_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), conn_ptr);
	} else {
		char *peer = bpf_map_lookup_elem(&tcp_target, &key);
		if (peer) {
			bpf_probe_read_kernel_str(e->target, sizeof(e->target), peer);
		} else {
			e->target[0] = '\0';
		}
	}
	bpf_map_delete_elem(&tcp_target, &key);
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);

	char *grpc_method_ptr = bpf_map_lookup_elem(&grpc_methods, &conn_key);
	if (grpc_method_ptr) {
		struct event *eg = get_event_buf();
		if (eg) {
			eg->timestamp  = bpf_ktime_get_ns();
			eg->pid        = pid;
			eg->type       = EVENT_GRPC_METHOD;
			eg->latency_ns = latency_ns;
			eg->error      = ret < 0 ? (s32)ret : 0;
			eg->bytes      = bytes;
			eg->tcp_state  = 0;
			eg->details[0] = '\0';
			bpf_probe_read_kernel_str(eg->target, sizeof(eg->target), grpc_method_ptr);
			capture_user_stack(ctx, pid, tid, eg);
			bpf_ringbuf_output(&events, eg, sizeof(*eg), 0);
		}
		bpf_map_delete_elem(&grpc_methods, &conn_key);
	}

	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_RECVMSG);
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	stash_tcp_peer(ctx, PAIR_TCP_RECVMSG);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_RECVMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TCP_RECV;
	e->latency_ns = calc_latency(*start_ts);
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;

	u64 conn_key = get_key(pid, tid);
	char *conn_ptr = bpf_map_lookup_elem(&socket_conns, &conn_key);
	if (conn_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), conn_ptr);
	} else {
		char *peer = bpf_map_lookup_elem(&tcp_target, &key);
		if (peer) {
			bpf_probe_read_kernel_str(e->target, sizeof(e->target), peer);
		} else {
			e->target[0] = '\0';
		}
	}
	bpf_map_delete_elem(&tcp_target, &key);
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/getaddrinfo")
int uprobe_getaddrinfo(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_GETADDRINFO);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	void *node_ptr = (void *)PT_REGS_PARM1(ctx);
	if (node_ptr) {
		char target[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(target, sizeof(target), node_ptr);
		bpf_map_update_elem(&dns_targets, &key, target, BPF_ANY);
	}
	
	return 0;
}

SEC("uretprobe/getaddrinfo")
int uretprobe_getaddrinfo(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_GETADDRINFO);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	u64 latency = calc_latency(*start_ts);
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_DNS;
	e->latency_ns = latency;
	e->bytes = 0;
	e->tcp_state = 0;
	
	s64 ret = PT_REGS_RC(ctx);
	if (ret == 0) {
		e->error = 0;
	} else {
		e->error = ret;
	}
	
	char *target_ptr = bpf_map_lookup_elem(&dns_targets, &key);
	if (target_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), target_ptr);
		bpf_map_delete_elem(&dns_targets, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

struct inet_sock_set_state_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, skaddr) == 8, "inet_sock_set_state: skaddr must be at offset 8");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, oldstate) == 16, "inet_sock_set_state: oldstate must be at offset 16");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, newstate) == 20, "inet_sock_set_state: newstate must be at offset 20");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, sport) == 24, "inet_sock_set_state: sport must be at offset 24");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, dport) == 26, "inet_sock_set_state: dport must be at offset 26");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, family) == 28, "inet_sock_set_state: family must be at offset 28");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, protocol) == 30, "inet_sock_set_state: protocol must be at offset 30");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, saddr) == 32, "inet_sock_set_state: saddr must be at offset 32");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, daddr) == 36, "inet_sock_set_state: daddr must be at offset 36");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, saddr_v6) == 40, "inet_sock_set_state: saddr_v6 must be at offset 40");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, daddr_v6) == 56, "inet_sock_set_state: daddr_v6 must be at offset 56");

SEC("tp/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(void *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct inet_sock_set_state_args args_local;
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}
	if (args_local.protocol != IPPROTO_TCP) {
		return 0;
	}

	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TCP_STATE;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = args_local.newstate;
	e->target[0] = '\0';

	if (args_local.family == AF_INET6) {
		format_ipv6_port(args_local.daddr_v6, args_local.dport, e->target);
	} else {
		u32 daddr = ((u32)args_local.daddr[0] << 24) |
		            ((u32)args_local.daddr[1] << 16) |
		            ((u32)args_local.daddr[2] << 8) |
		            (u32)args_local.daddr[3];
		if (daddr != 0) {
			format_ip_port(daddr, args_local.dport, e->target);
		}
	}
	capture_user_stack(ctx, pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

struct tcp_retransmit_skb_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, skbaddr) == 8, "tcp_retransmit_skb: skbaddr must be at offset 8");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, skaddr) == 16, "tcp_retransmit_skb: skaddr must be at offset 16");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, state) == 24, "tcp_retransmit_skb: state must be at offset 24");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, sport) == 28, "tcp_retransmit_skb: sport must be at offset 28");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, dport) == 30, "tcp_retransmit_skb: dport must be at offset 30");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, family) == 32, "tcp_retransmit_skb: family must be at offset 32");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, saddr) == 34, "tcp_retransmit_skb: saddr must be at offset 34");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, daddr) == 38, "tcp_retransmit_skb: daddr must be at offset 38");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, saddr_v6) == 42, "tcp_retransmit_skb: saddr_v6 must be at offset 42");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, daddr_v6) == 58, "tcp_retransmit_skb: daddr_v6 must be at offset 58");

SEC("tp/tcp/tcp_retransmit_skb")
int tracepoint_tcp_retransmit_skb(void *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct tcp_retransmit_skb_args args_local;
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TCP_RETRANS;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';

	if (args_local.family == AF_INET6) {
		format_ipv6_port(args_local.daddr_v6, args_local.dport, e->target);
	} else {
		u32 daddr = ((u32)args_local.daddr[0] << 24) |
		            ((u32)args_local.daddr[1] << 16) |
		            ((u32)args_local.daddr[2] << 8) |
		            (u32)args_local.daddr[3];
		if (daddr != 0) {
			format_ip_port(daddr, args_local.dport, e->target);
		}
	}
	capture_user_stack(ctx, pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

struct net_dev_xmit_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *skbaddr;
	unsigned int len;
	int rc;
	unsigned int name_loc;
};
_Static_assert(__builtin_offsetof(struct net_dev_xmit_args, len) == 16, "net_dev_xmit: len must be at offset 16");
_Static_assert(__builtin_offsetof(struct net_dev_xmit_args, rc) == 20, "net_dev_xmit: rc must be at offset 20");
_Static_assert(__builtin_offsetof(struct net_dev_xmit_args, name_loc) == 24, "net_dev_xmit: name __data_loc must be at offset 24");

SEC("tp/net/net_dev_xmit")
int tracepoint_net_dev_xmit(void *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct net_dev_xmit_args args_local;
	bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx);
	if (args_local.rc == 0) {
		return 0;
	}
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_NET_DEV_ERROR;
	e->latency_ns = 0;
	e->error = args_local.rc;
	e->bytes = args_local.len;
	e->tcp_state = 0;
	unsigned short name_off = (unsigned short)(args_local.name_loc & 0xffff);
	bpf_probe_read_kernel_str(e->target, sizeof(e->target), (char *)ctx + name_off);
	capture_user_stack(ctx, pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_UDP_SENDMSG);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_sendmsg")
int kretprobe_udp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_UDP_SENDMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_UDP_SEND;
	e->latency_ns = calc_latency(*start_ts);
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_UDP_RECVMSG);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_UDP_RECVMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_UDP_RECV;
	e->latency_ns = calc_latency(*start_ts);
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/http_request")
int uprobe_http_request(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_HTTP_REQUEST);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	char *url = (char *)PT_REGS_PARM1(ctx);
	if (url) {
		char url_buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(url_buf, sizeof(url_buf), url);
		u64 conn_key = get_key(pid, tid);
		bpf_map_update_elem(&socket_conns, &conn_key, url_buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/http_request")
int uretprobe_http_request(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_HTTP_REQUEST);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_HTTP_REQ;
	e->latency_ns = calc_latency(*start_ts);
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	
	u64 conn_key = get_key(pid, tid);
	char *url_ptr = bpf_map_lookup_elem(&socket_conns, &conn_key);
	if (url_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), url_ptr);
		bpf_map_delete_elem(&socket_conns, &conn_key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/http_response")
int uprobe_http_response(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_HTTP_RESPONSE);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/http_response")
int uretprobe_http_response(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_HTTP_RESPONSE);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_HTTP_RESP;
	e->latency_ns = calc_latency(*start_ts);
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/PQexec")
int uprobe_PQexec(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_PQEXEC);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	char *query = (char *)PT_REGS_PARM2(ctx);
	if (query) {
		char buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(buf, sizeof(buf), query);
		u32 i;
		for (i = 0; i < MAX_STRING_LEN; i++) {
			if (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t' || buf[i] == '\0') {
				buf[i] = '\0';
				break;
			}
		}
		bpf_map_update_elem(&db_queries, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/PQexec")
int uretprobe_PQexec(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_PQEXEC);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_DB_QUERY;
	e->latency_ns = latency;
	long ret = PT_REGS_RC(ctx);
	e->error = ret == 0 ? -1 : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	char *qptr = bpf_map_lookup_elem(&db_queries, &key);
	if (qptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), qptr);
		bpf_map_delete_elem(&db_queries, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/mysql_real_query")
int uprobe_mysql_real_query(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_MYSQL_QUERY);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	const char *query = (const char *)PT_REGS_PARM2(ctx);
	if (query) {
		char buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(buf, sizeof(buf), query);
		u32 i;
		for (i = 0; i < MAX_STRING_LEN; i++) {
			if (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t' || buf[i] == '\0') {
				buf[i] = '\0';
				break;
			}
		}
		bpf_map_update_elem(&db_queries, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/mysql_real_query")
int uretprobe_mysql_real_query(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_MYSQL_QUERY);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_DB_QUERY;
	e->latency_ns = latency;
	long ret = PT_REGS_RC(ctx);
	e->error = ret;
	e->bytes = 0;
	e->tcp_state = 0;
	char *qptr = bpf_map_lookup_elem(&db_queries, &key);
	if (qptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), qptr);
		bpf_map_delete_elem(&db_queries, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}
SEC("uprobe/SSL_connect")
int uprobe_SSL_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_SSL_CONNECT);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_connect")
int uretprobe_SSL_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_SSL_CONNECT);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = calc_latency(*start_ts);
	long ret = PT_REGS_RC(ctx);
	e->error = ret <= 0 ? ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/SSL_accept")
int uprobe_SSL_accept(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_SSL_ACCEPT);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_accept")
int uretprobe_SSL_accept(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_SSL_ACCEPT);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = calc_latency(*start_ts);
	long ret = PT_REGS_RC(ctx);
	e->error = ret <= 0 ? ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/SSL_do_handshake")
int uprobe_SSL_do_handshake(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_SSL_DO_HANDSHAKE);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_do_handshake")
int uretprobe_SSL_do_handshake(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_SSL_DO_HANDSHAKE);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = calc_latency(*start_ts);
	long ret = PT_REGS_RC(ctx);
	e->error = ret <= 0 ? ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/gnutls_handshake")
int uprobe_gnutls_handshake(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_GNUTLS_HANDSHAKE);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_handshake")
int uretprobe_gnutls_handshake(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_GNUTLS_HANDSHAKE);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = calc_latency(*start_ts);
	long ret = PT_REGS_RC(ctx);
	e->error = ret < 0 ? ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/mbedtls_ssl_handshake")
int uprobe_mbedtls_ssl_handshake(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_MBEDTLS_HANDSHAKE);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/mbedtls_ssl_handshake")
int uretprobe_mbedtls_ssl_handshake(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_MBEDTLS_HANDSHAKE);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = calc_latency(*start_ts);
	long ret = PT_REGS_RC(ctx);
	e->error = ret < 0 ? ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}
