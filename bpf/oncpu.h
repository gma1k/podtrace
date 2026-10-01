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

static __always_inline int oncpu_request_open(struct oncpu_thread_request *r, u64 now)
{
	if (now - r->correlation_id > ONCPU_REQUEST_MAX_NS)
		return 0;
	if (r->kind == ONCPU_KIND_HTTP1) {
		u64 conn = r->conn;
		struct http_req *live = bpf_map_lookup_elem(&http_reqs, &conn);
		return live && live->start_ns == r->correlation_id;
	}
	if (r->kind == ONCPU_KIND_H2) {
		struct h2_stream_key k = {.conn = r->conn, .stream = (u32)r->stream};
		struct h2_stream_state *st = bpf_map_lookup_elem(&h2_streams, &k);
		return st && st->start_ns == r->correlation_id;
	}
	return 1;
}

static __always_inline void oncpu_note_thread_conn(u64 conn)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	if (!bpf_map_lookup_elem(&oncpu_event_loop_threads, &tid))
		return;
	bpf_map_update_elem(&oncpu_thread_conns, &tid, &conn, BPF_ANY);
}

static __always_inline void oncpu_note_socket(u64 sk)
{
	if (!oncpu_is_enabled())
		return;
	u64 *alias = bpf_map_lookup_elem(&oncpu_conn_aliases, &sk);
	oncpu_note_thread_conn(alias ? *alias : sk);
}

static __always_inline void oncpu_alias_socket(u64 sk, u64 conn)
{
	if (oncpu_is_enabled() && sk && conn)
		bpf_map_update_elem(&oncpu_conn_aliases, &sk, &conn, BPF_ANY);
}

static __always_inline void oncpu_begin_thread_request(u32 kind, u64 conn, u64 stream,
						       u64 correlation_id)
{
	if (!oncpu_is_enabled() || oncpu_is_go_proc())
		return;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct oncpu_thread_request *prev = bpf_map_lookup_elem(&oncpu_thread_requests, &tid);
	if (prev && prev->conn != conn && oncpu_request_open(prev, correlation_id)) {
		u8 one = 1;
		bpf_map_update_elem(&oncpu_event_loop_threads, &tid, &one, BPF_ANY);
	}
	struct oncpu_thread_request r = {
		.correlation_id = correlation_id,
		.conn = conn,
		.stream = stream,
		.kind = kind,
	};
	bpf_map_update_elem(&oncpu_thread_requests, &tid, &r, BPF_ANY);
	bpf_map_update_elem(&oncpu_conn_requests, &conn, &r, BPF_ANY);
	oncpu_note_thread_conn(conn);
}

static __always_inline void oncpu_finish_thread_request(u64 conn, u64 correlation_id,
							u64 latency_ns)
{
	if (!oncpu_is_enabled() || oncpu_is_go_proc())
		return;
	oncpu_record_done(correlation_id, latency_ns);

	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct oncpu_thread_request *r = bpf_map_lookup_elem(&oncpu_thread_requests, &tid);
	if (r && r->correlation_id == correlation_id)
		bpf_map_delete_elem(&oncpu_thread_requests, &tid);
	struct oncpu_thread_request *c = bpf_map_lookup_elem(&oncpu_conn_requests, &conn);
	if (c && c->correlation_id == correlation_id)
		bpf_map_delete_elem(&oncpu_conn_requests, &conn);
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
