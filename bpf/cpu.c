// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

/* EVENT_SCHED_SWITCH carries OFF-CPU (blocked/runqueue-wait) time. The
 * previous implementation stamped at switch-IN and emitted at switch-OUT,
 * which measures the ON-CPU slice — the exact inverse of the "thread
 * blocked" message every consumer renders.
 *
 * Measuring off-CPU time needs the stamp at switch-out and the delta at the
 * next switch-in. But at switch-in the current task is still `prev` (the
 * tracepoint fires before the context switch completes), so emitting there
 * would attribute the event to the wrong task's cgroup/comm. Instead the
 * blocked interval is parked in sched_pending_blocked and emitted at the
 * task's NEXT switch-out, when the task itself is current and
 * get_event_buf() fills the right identity — which also lets the event carry
 * the task's TGID like every other event type (the old code emitted the raw
 * TID). */
struct sched_switch_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char prev_comm[16];
	u32 prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	u32 next_pid;
	int next_prio;
};
_Static_assert(__builtin_offsetof(struct sched_switch_args, prev_comm) == 8, "sched_switch: prev_comm must be at offset 8");
_Static_assert(__builtin_offsetof(struct sched_switch_args, prev_pid) == 24, "sched_switch: prev_pid must be at offset 24");
_Static_assert(__builtin_offsetof(struct sched_switch_args, prev_state) == 32, "sched_switch: prev_state must be at offset 32");
_Static_assert(__builtin_offsetof(struct sched_switch_args, next_comm) == 40, "sched_switch: next_comm must be at offset 40");
_Static_assert(__builtin_offsetof(struct sched_switch_args, next_pid) == 56, "sched_switch: next_pid must be at offset 56");

SEC("tp/sched/sched_switch")
int tracepoint_sched_switch(void *ctx) {
	struct sched_switch_args args_local = {};
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}

	u32 prev_pid = args_local.prev_pid;
	u32 next_pid = args_local.next_pid;
	u64 now = bpf_ktime_get_ns();

	/* The task coming on-CPU just finished an off-CPU interval. */
	if (next_pid > 0) {
		u64 *out_ts = bpf_map_lookup_elem(&sched_out_ts, &next_pid);
		if (out_ts) {
			u64 blocked = now > *out_ts ? now - *out_ts : 0;
			bpf_map_delete_elem(&sched_out_ts, &next_pid);
			if (blocked > MIN_LATENCY_NS) {
				bpf_map_update_elem(&sched_pending_blocked, &next_pid, &blocked, BPF_ANY);
			}
		}
	}

	/* The task going off-CPU is current here: emit its parked interval with
	 * correct attribution, then stamp this switch-out. */
	if (prev_pid > 0) {
		u64 *pending = bpf_map_lookup_elem(&sched_pending_blocked, &prev_pid);
		if (pending) {
			u64 blocked = *pending;
			bpf_map_delete_elem(&sched_pending_blocked, &prev_pid);

			struct event *e = get_event_buf();
			if (e) {
				e->timestamp = now;
				e->pid = bpf_get_current_pid_tgid() >> 32;
				e->type = EVENT_SCHED_SWITCH;
				e->latency_ns = blocked;
				e->error = 0;
				e->bytes = 0;
				e->tcp_state = 0;
				e->target[0] = '\0';
				e->details[0] = '\0';

				capture_user_stack(ctx, e->pid, prev_pid, e);
				bpf_ringbuf_output(&events, e, sizeof(*e), 0);
			}
		}
		bpf_map_update_elem(&sched_out_ts, &prev_pid, &now, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/do_futex")
int kprobe_do_futex(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_FUTEX);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	long *uaddr = (long *)PT_REGS_PARM1(ctx);
	if (uaddr) {
		char buf[MAX_STRING_LEN] = {};
		u64 addr = (u64)uaddr;
		u32 idx = 0;
		if (idx < MAX_STRING_LEN - 2) {
			buf[idx++] = '0';
			buf[idx++] = 'x';
		}
		u32 max_idx = MAX_STRING_LEN - 1;
		for (int i = 0; i < HEX_ADDR_LEN && idx < max_idx; i++) {
			u8 nibble = (addr >> ((HEX_ADDR_LEN - 1 - i) * 4)) & 0xF;
			if (nibble < 10) {
				buf[idx++] = '0' + nibble;
			} else {
				buf[idx++] = 'a' + (nibble - 10);
			}
		}
		buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
		bpf_map_update_elem(&lock_targets, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("kretprobe/do_futex")
int kretprobe_do_futex(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_FUTEX);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	if (latency < MIN_LATENCY_NS) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	long ret = PT_REGS_RC(ctx);
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_LOCK_CONTENTION;
	e->latency_ns = latency;
	e->error = ret;
	e->bytes = 0;
	e->tcp_state = 0;
	char *name_ptr = bpf_map_lookup_elem(&lock_targets, &key);
	if (name_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), name_ptr);
		bpf_map_delete_elem(&lock_targets, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/pthread_mutex_lock")
int uprobe_pthread_mutex_lock(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_PTHREAD_MUTEX);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	void *mutex = (void *)PT_REGS_PARM1(ctx);
	if (mutex) {
		char buf[MAX_STRING_LEN] = {};
		u64 addr = (u64)mutex;
		u32 idx = 0;
		if (idx < MAX_STRING_LEN - 10) {
			buf[idx++] = 'm';
			buf[idx++] = 't';
			buf[idx++] = 'x';
			buf[idx++] = '@';
		}
		if (idx < MAX_STRING_LEN - 2) {
			buf[idx++] = '0';
			buf[idx++] = 'x';
		}
		u32 max_idx = MAX_STRING_LEN - 1;
		for (int i = 0; i < HEX_ADDR_LEN && idx < max_idx; i++) {
			u8 nibble = (addr >> ((HEX_ADDR_LEN - 1 - i) * 4)) & 0xF;
			if (nibble < 10) {
				buf[idx++] = '0' + nibble;
			} else {
				buf[idx++] = 'a' + (nibble - 10);
			}
		}
		buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
		bpf_map_update_elem(&lock_targets, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int uretprobe_pthread_mutex_lock(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_PTHREAD_MUTEX);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	if (latency < MIN_LATENCY_NS) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	long ret = PT_REGS_RC(ctx);
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_LOCK_CONTENTION;
	e->latency_ns = latency;
	e->error = ret;
	e->bytes = 0;
	e->tcp_state = 0;
	char *name_ptr = bpf_map_lookup_elem(&lock_targets, &key);
	if (name_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), name_ptr);
		bpf_map_delete_elem(&lock_targets, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}