// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

SEC("tp/exceptions/page_fault_user")
int tracepoint_page_fault_user(void *ctx) {
	// NOTE: Tracepoint argument layouts can differ across kernels/distros when using raw tracepoints.
	// For stability, avoid relying on tracepoint "common_pid" field offsets here and use the
	// current task PID from bpf_get_current_pid_tgid().
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Sample 1 in PAGE_FAULT_SAMPLE_RATE faults per CPU. Emitting every
	 * fault (each with a user-stack capture) saturates the ring buffer and
	 * evicts every other event type on busy workloads. */
	u32 zero = 0;
	u64 *seq = bpf_map_lookup_elem(&page_fault_seq, &zero);
	if (!seq) {
		return 0;
	}
	*seq += 1;
	if (*seq % PAGE_FAULT_SAMPLE_RATE != 0) {
		return 0;
	}

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_PAGE_FAULT;
	e->latency_ns = 0;
	// Best-effort: omit error_code (layout is not stable without BTF-typed tracepoints).
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, e->pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

/* There is no tp/oom/oom_kill_process tracepoint upstream — the oom group
 * exposes mark_victim (one fire per killed task). The previous handler
 * targeted the nonexistent name and silently never attached, so
 * EVENT_OOM_KILL was dead on every mainline kernel.
 *
 * mark_victim's guaranteed field on all kernels since 4.19 is `int pid` at
 * offset 8. Kernel 6.10 added comm (__data_loc), total_vm, rss counters and
 * uid behind it. The pinned struct matches the 6.10+ layout; the __data_loc
 * descriptor for comm is sanity-checked before use so pre-6.10 kernels
 * (where those bytes are past the record) degrade to a pid-only event
 * instead of emitting garbage. */
struct oom_mark_victim_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int pid;
	unsigned int comm_loc;  /* __data_loc char[] comm, kernels >= 6.10 */
	u64 total_vm;           /* kernels >= 6.10 */
	u64 anon_rss;
	u64 file_rss;
	u64 shmem_rss;
};
_Static_assert(__builtin_offsetof(struct oom_mark_victim_args, pid) == 8, "mark_victim: pid must be at offset 8");
_Static_assert(__builtin_offsetof(struct oom_mark_victim_args, comm_loc) == 12, "mark_victim: comm __data_loc must be at offset 12");
_Static_assert(__builtin_offsetof(struct oom_mark_victim_args, total_vm) == 16, "mark_victim: total_vm must be at offset 16");

SEC("tp/oom/mark_victim")
int tracepoint_oom_mark_victim(void *ctx) {
	struct oom_mark_victim_args args_local = {};
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}

	/* mark_victim fires in the OOM-killing task's context, not the
	 * victim's, so skip the in-kernel cgroup prefilter and let the
	 * userspace filter judge the victim PID. */
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = args_local.pid;
	e->type = EVENT_OOM_KILL;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';

	/* Resolve the victim comm from the __data_loc descriptor, but only when
	 * it looks like one (offset within the record page, length bounded by
	 * TASK_COMM_LEN) — on pre-6.10 kernels these bytes are not part of the
	 * record and must be ignored. */
	unsigned short comm_off = (unsigned short)(args_local.comm_loc & 0xffff);
	unsigned short comm_len = (unsigned short)(args_local.comm_loc >> 16);
	if (comm_off >= sizeof(struct oom_mark_victim_args) && comm_off < 4096 &&
	    comm_len > 0 && comm_len <= COMM_LEN + 1) {
		bpf_probe_read_kernel_str(e->target, COMM_LEN, (char *)ctx + comm_off);
		__builtin_memcpy(e->comm, e->target, COMM_LEN);
	}

	capture_user_stack(ctx, e->pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}
