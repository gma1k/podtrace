// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_HELPERS_H
#define PODTRACE_HELPERS_H

#include "common.h"
#include "maps.h"

static inline u64 get_key(u32 pid, u32 tid) {
	return ((u64)pid << 32) | tid;
}

static inline struct pair_key make_pair_key(u32 pair) {
	struct pair_key k = {};
	k.pid_tgid = bpf_get_current_pid_tgid();
	k.pair = pair;
	return k;
}

static inline void record_start_time(const struct pair_key *key) {
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, key, &ts, BPF_ANY);
}

static inline u64 calc_latency(u64 start) {
	u64 now = bpf_ktime_get_ns();
	return now > start ? now - start : 0;
}

static __attribute__((noinline)) u32 append_dec(char *buf, u32 idx, u32 max_idx, u32 val) {
	u32 divisor = 10000;
	int started = 0;
	for (int i = 0; i < 5; i++) {
		u32 digit = (val / divisor) % 10;
		if (digit != 0 || started || divisor == 1) {
			if (idx < max_idx) buf[idx++] = '0' + digit;
			started = 1;
		}
		divisor /= 10;
	}
	return idx;
}

static inline void format_ip_port(u32 ip, u16 port, char *buf) {
	u8 a = (ip >> 24) & 0xFF;
	u8 b = (ip >> 16) & 0xFF;
	u8 c = (ip >> 8) & 0xFF;
	u8 d = ip & 0xFF;
	u32 idx = 0;
	u32 max_idx = MAX_STRING_LEN - 1;

	idx = append_dec(buf, idx, max_idx, a);
	if (idx < max_idx) buf[idx++] = '.';
	idx = append_dec(buf, idx, max_idx, b);
	if (idx < max_idx) buf[idx++] = '.';
	idx = append_dec(buf, idx, max_idx, c);
	if (idx < max_idx) buf[idx++] = '.';
	idx = append_dec(buf, idx, max_idx, d);
	if (idx < max_idx) buf[idx++] = ':';
	idx = append_dec(buf, idx, max_idx, port);
	buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
}

static inline void format_ipv6_port(const u8 *ipv6, u16 port, char *buf) {
	u16 p = port;
	u32 idx = 0;
	u32 max_idx = MAX_STRING_LEN - 1;
	u32 port_start_limit = MAX_STRING_LEN - 6;
	
	for (int i = 0; i < 8 && idx < port_start_limit; i++) {
		if (i > 0 && idx < max_idx) {
			buf[idx++] = ':';
		}
		if (idx >= max_idx) break;
		u16 seg = (ipv6[i*2] << 8) | ipv6[i*2 + 1];
		u8 d1 = (seg >> 12) & 0xF;
		u8 d2 = (seg >> 8) & 0xF;
		u8 d3 = (seg >> 4) & 0xF;
		u8 d4 = seg & 0xF;
		
		if (d1 > 0 && idx < max_idx) {
			buf[idx++] = d1 < 10 ? '0' + d1 : 'a' + (d1 - 10);
		}
		if (idx < max_idx) buf[idx++] = d2 < 10 ? '0' + d2 : 'a' + (d2 - 10);
		if (idx < max_idx) buf[idx++] = d3 < 10 ? '0' + d3 : 'a' + (d3 - 10);
		if (idx < max_idx) buf[idx++] = d4 < 10 ? '0' + d4 : 'a' + (d4 - 10);
	}
	
	if (idx < port_start_limit) {
		if (idx < max_idx) buf[idx++] = ':';
		idx = append_dec(buf, idx, max_idx, p);
	}
	buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
}

/* 64-bit finalizer hash — reduces collision probability vs plain XOR */
static inline u64 build_stack_key(u32 pid, u32 tid, u64 timestamp) {
	u64 h = (((u64)pid << 32) | tid) ^ timestamp;
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return h;
}

static inline struct event *get_event_buf_unfiltered(void) {
	u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&event_buf, &zero);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->cgroup_id = bpf_get_current_cgroup_id();
		bpf_get_current_comm(&e->comm, sizeof(e->comm));

#ifdef PODTRACE_VMLINUX_FROM_BTF
		struct task_struct *__task = (struct task_struct *)bpf_get_current_task();
		if (__task) {
			e->net_ns_id = BPF_CORE_READ(__task, nsproxy, net_ns, ns.inum);
		}
#endif
	}
	return e;
}

static inline struct event *get_event_buf(void) {
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return NULL;
	}

	u32 zero = 0;
	u32 *enabled = bpf_map_lookup_elem(&cgroup_filter_enabled, &zero);
	if (enabled && *enabled) {
		u64 cgid = e->cgroup_id;
		u8 *allowed = bpf_map_lookup_elem(&target_cgroup_ids, &cgid);
		if (!allowed) {
			return NULL;
		}
	}
	return e;
}

static inline void capture_user_stack(void *ctx, u32 pid, u32 tid, struct event *e) {
	if (!e) {
		return;
	}
	u32 zero = 0;
	struct stack_trace_t *trace = bpf_map_lookup_elem(&stack_buf, &zero);
	if (!trace) {
		e->stack_key = 0;
		return;
	}
	trace->nr = 0;
	int sz = bpf_get_stack(ctx, trace->ips, sizeof(trace->ips), BPF_F_USER_STACK);
	if (sz <= 0) {
		e->stack_key = 0;
		return;
	}
	u32 max_frames = sizeof(trace->ips) / sizeof(u64);
	u32 nr_frames = (u32)(sz / sizeof(u64));
	trace->nr = nr_frames > max_frames ? max_frames : nr_frames;
	u64 key = build_stack_key(pid, tid, e->timestamp);
	bpf_map_update_elem(&stack_traces, &key, trace, BPF_ANY);
	e->stack_key = key;
}

#endif
