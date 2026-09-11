// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "agg.h"


#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GO_ACQUIRE_GOROUTINE(ctx) ((u64)(ctx)->r14)
#define GO_ACQUIRE_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_ACQUIRE_GOROUTINE(ctx) ((u64)(ctx)->regs[28])
#define GO_ACQUIRE_SUPPORTED 1
#endif


#ifdef GO_ACQUIRE_SUPPORTED

// database/sql.(*DB).conn is where a caller blocks for a free pooled
// connection, so entry-to-return is the pool wait itself. No struct field is
// read: the duration alone is the signal, which is why this probe needs no
// per-Go-version offset table and does not care how database/sql is laid out.
//
// The key is the goroutine pointer (r14 on x86, x28 on arm64), not the thread
// id. A goroutine waiting on a free connection is precisely the case where
// Go's scheduler parks it and may resume it on a different OS thread, so
// pairing on pid_tgid would mismatch every wait that actually blocked -- the
// only ones worth recording.

SEC("uprobe/go_db_conn")
int uprobe_go_db_conn(struct pt_regs *ctx)
{
	u64 key = GO_ACQUIRE_GOROUTINE(ctx);
	u64 now = bpf_ktime_get_ns();

	if (key == 0)
		return 0;

	bpf_map_update_elem(&go_acquire_starts, &key, &now, BPF_ANY);
	return 0;
}

SEC("uprobe/go_db_conn_ret")
int uprobe_go_db_conn_ret(struct pt_regs *ctx)
{
	u64 key = GO_ACQUIRE_GOROUTINE(ctx);
	if (key == 0)
		return 0;

	u64 *start = bpf_map_lookup_elem(&go_acquire_starts, &key);
	if (!start)
		return 0;

	u64 began = *start;
	// Dropped before any other early return: a stale start would pair with
	// some later acquisition on the same goroutine and report a wait that
	// never happened.
	bpf_map_delete_elem(&go_acquire_starts, &key);

	u64 now = bpf_ktime_get_ns();
	if (now <= began)
		return 0;

	u64 wait = now - began;

	// Below the floor the call took a free connection straight off the pool's
	// free list. Go counts only blocking acquisitions in DBStats.WaitCount,
	// so dropping these keeps the metric's meaning the same as the number
	// application authors already reason about.
	if (wait < MIN_LATENCY_NS)
		return 0;

	struct event *e = get_event_buf();
	if (!e)
		return 0;

	e->timestamp = now;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->type = EVENT_DB_ACQUIRE;
	e->latency_ns = wait;

	if (agg_absorbed(e, 0))
		return 0;

	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

#else

SEC("uprobe/go_db_conn")
int uprobe_go_db_conn(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_db_conn_ret")
int uprobe_go_db_conn_ret(struct pt_regs *ctx) { return 0; }

#endif
