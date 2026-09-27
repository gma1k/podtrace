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

static __always_inline void oncpu_begin_request(u64 conn, u64 correlation_id)
{
	if (!oncpu_is_enabled())
		return;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct oncpu_thread_request r = {.correlation_id = correlation_id, .conn = conn};
	bpf_map_update_elem(&oncpu_thread_requests, &tid, &r, BPF_ANY);
}

static __always_inline void oncpu_finish_request(u64 correlation_id, u64 latency_ns)
{
	if (!oncpu_is_enabled())
		return;
	struct oncpu_request_done done = {
		.latency_ns = latency_ns,
		.cgroup_id = bpf_get_current_cgroup_id(),
	};
	bpf_map_update_elem(&oncpu_requests_done, &correlation_id, &done, BPF_ANY);

	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct oncpu_thread_request *r = bpf_map_lookup_elem(&oncpu_thread_requests, &tid);
	if (r && r->correlation_id == correlation_id)
		bpf_map_delete_elem(&oncpu_thread_requests, &tid);
}

static __always_inline u64 oncpu_active_request(u32 tid)
{
	struct oncpu_thread_request *r = bpf_map_lookup_elem(&oncpu_thread_requests, &tid);
	if (!r)
		return 0;
	u64 conn = r->conn;
	u64 correlation_id = r->correlation_id;
	struct http_req *live = bpf_map_lookup_elem(&http_reqs, &conn);
	if (!live || live->start_ns != correlation_id) {
		bpf_map_delete_elem(&oncpu_thread_requests, &tid);
		return 0;
	}
	return correlation_id;
}

#endif
