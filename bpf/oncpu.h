// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_ONCPU_H
#define PODTRACE_ONCPU_H

#include "common.h"
#include "maps.h"

static __always_inline int oncpu_is_enabled(void)
{
	u32 zero = 0;
	u32 *enabled = bpf_map_lookup_elem(&oncpu_enabled, &zero);
	return enabled && *enabled;
}

static __always_inline int oncpu_is_go_proc(void)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&oncpu_go_procs, &tgid) != NULL;
}

static __always_inline void oncpu_record_done(u64 correlation_id, u64 latency_ns)
{
	struct oncpu_request_done done = {
		.latency_ns = latency_ns,
		.cgroup_id = bpf_get_current_cgroup_id(),
	};
	bpf_map_update_elem(&oncpu_requests_done, &correlation_id, &done, BPF_ANY);
}

static __always_inline void oncpu_begin_thread_request(u32 kind, u64 conn, u64 stream,
						       u64 correlation_id)
{
	if (!oncpu_is_enabled() || oncpu_is_go_proc())
		return;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct oncpu_thread_request r = {
		.correlation_id = correlation_id,
		.conn = conn,
		.stream = stream,
		.kind = kind,
	};
	bpf_map_update_elem(&oncpu_thread_requests, &tid, &r, BPF_ANY);
}

static __always_inline void oncpu_finish_thread_request(u64 correlation_id, u64 latency_ns)
{
	if (!oncpu_is_enabled() || oncpu_is_go_proc())
		return;
	oncpu_record_done(correlation_id, latency_ns);

	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct oncpu_thread_request *r = bpf_map_lookup_elem(&oncpu_thread_requests, &tid);
	if (r && r->correlation_id == correlation_id)
		bpf_map_delete_elem(&oncpu_thread_requests, &tid);
}

static __always_inline void oncpu_begin_goroutine(u64 goroutine, u32 kind, u64 correlation_id)
{
	if (!goroutine || !oncpu_is_enabled())
		return;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	u8 one = 1;
	bpf_map_update_elem(&oncpu_go_procs, &tgid, &one, BPF_ANY);

	struct oncpu_goroutine_key k = {.tgid = tgid, .goroutine = goroutine};
	struct oncpu_goroutine_request *cur = bpf_map_lookup_elem(&oncpu_goroutine_requests, &k);
	if (cur && cur->kind != kind &&
	    correlation_id - cur->correlation_id < ONCPU_REQUEST_MAX_NS)
		return;
	struct oncpu_goroutine_request r = {.correlation_id = correlation_id, .kind = kind};
	bpf_map_update_elem(&oncpu_goroutine_requests, &k, &r, BPF_ANY);
}

static __always_inline void oncpu_finish_goroutine(u64 goroutine, u32 kind)
{
	if (!goroutine || !oncpu_is_enabled())
		return;
	struct oncpu_goroutine_key k = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
		.goroutine = goroutine,
	};
	struct oncpu_goroutine_request *r = bpf_map_lookup_elem(&oncpu_goroutine_requests, &k);
	if (!r || r->kind != kind)
		return;
	u64 correlation_id = r->correlation_id;
	u64 now = bpf_ktime_get_ns();
	oncpu_record_done(correlation_id, now > correlation_id ? now - correlation_id : 0);
	bpf_map_delete_elem(&oncpu_goroutine_requests, &k);
}

static __always_inline void oncpu_abandon_goroutine(u64 goroutine, u32 kind)
{
	if (!goroutine || !oncpu_is_enabled())
		return;
	struct oncpu_goroutine_key k = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
		.goroutine = goroutine,
	};
	struct oncpu_goroutine_request *r = bpf_map_lookup_elem(&oncpu_goroutine_requests, &k);
	if (r && r->kind == kind)
		bpf_map_delete_elem(&oncpu_goroutine_requests, &k);
}

#endif
