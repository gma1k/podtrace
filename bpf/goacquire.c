// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "agg.h"


#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GO_ACQUIRE_GOROUTINE(ctx) ((u64)(ctx)->r14)
#define GO_ACQUIRE_RECV(ctx)      ((u64)(ctx)->ax)
#define GO_ACQUIRE_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_ACQUIRE_GOROUTINE(ctx) ((u64)(ctx)->regs[28])
#define GO_ACQUIRE_RECV(ctx)      ((u64)PT_REGS_PARM1(ctx))
#define GO_ACQUIRE_SUPPORTED 1
#endif

#define POOL_STATS_INTERVAL_NS (1000ULL * 1000ULL * 1000ULL)


#ifdef GO_ACQUIRE_SUPPORTED

static __always_inline void emit_pool_stats(struct pt_regs *ctx, u64 now)
{
	u32 tgid = agent_ns_tgid();

	struct pool_field_offsets *off = bpf_map_lookup_elem(&pool_offsets, &tgid);
	if (!off)
		return;

	u64 db = GO_ACQUIRE_RECV(ctx);
	if (db == 0)
		return;

	s64 num_open = 0, max_open = 0;
	if (bpf_probe_read_user(&num_open, sizeof(num_open), (void *)(db + off->num_open)) != 0)
		return;
	if (bpf_probe_read_user(&max_open, sizeof(max_open), (void *)(db + off->max_open)) != 0)
		return;

	if (num_open < 0 || max_open < 0 || num_open > 1000000 || max_open > 1000000)
		return;

	u32 pct = 0;
	if (max_open > 0) {
		pct = (u32)((num_open * 100) / max_open);
		if (pct > 100)
			pct = 100;
	}

	struct pool_sample *s = bpf_map_lookup_elem(&pool_samples, &tgid);
	if (!s) {
		struct pool_sample fresh = {};
		fresh.last_emit_ns = now;
		bpf_map_update_elem(&pool_samples, &tgid, &fresh, BPF_ANY);
	} else {
		if ((u32)num_open > s->peak_open) {
			s->peak_open = (u32)num_open;
			s->peak_pct = pct;
			s->peak_max_open = (u32)max_open;
		}
		if (now <= s->last_emit_ns || (now - s->last_emit_ns) < POOL_STATS_INTERVAL_NS)
			return;

		if (s->peak_open > (u32)num_open) {
			num_open = s->peak_open;
			pct = s->peak_pct;
			max_open = s->peak_max_open;
		}
		s->last_emit_ns = now;
		s->peak_open = 0;
		s->peak_pct = 0;
		s->peak_max_open = 0;
	}

	struct event *e = get_event_buf();
	if (!e)
		return;

	e->timestamp = now;
	e->pid = agent_ns_tgid();
	e->type = EVENT_DB_POOL_STATS;
	e->error = (s32)pct;
	e->bytes = (u64)num_open;
	e->tcp_state = (u32)max_open;

	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

SEC("uprobe/go_db_conn")
int uprobe_go_db_conn(struct pt_regs *ctx)
{
	u64 key = GO_ACQUIRE_GOROUTINE(ctx);
	u64 now = bpf_ktime_get_ns();

	if (key == 0)
		return 0;

	bpf_map_update_elem(&go_acquire_starts, &key, &now, BPF_ANY);

	emit_pool_stats(ctx, now);
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
	bpf_map_delete_elem(&go_acquire_starts, &key);

	u64 now = bpf_ktime_get_ns();
	if (now <= began)
		return 0;

	u64 wait = now - began;

	if (wait < MIN_LATENCY_NS)
		return 0;

	struct event *e = get_event_buf();
	if (!e)
		return 0;

	e->timestamp = now;
	e->pid = agent_ns_tgid();
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
