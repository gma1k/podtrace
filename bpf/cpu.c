// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#define CPU_SAMPLE_WINDOW_NS (1000ULL * 1000ULL * 1000ULL)

static __always_inline void cpu_sample_accumulate(void *ctx, u64 on_cpu_ns, u64 now)
{
	u64 cgid = bpf_get_current_cgroup_id();

	if (!bpf_map_lookup_elem(&target_cgroup_ids, &cgid))
		return;

	struct cpu_window *w = bpf_map_lookup_elem(&cgroup_cpu_window, &cgid);
	if (!w) {
		struct cpu_window init = {.window_start_ns = now, .runtime_ns = on_cpu_ns};
		bpf_map_update_elem(&cgroup_cpu_window, &cgid, &init, BPF_ANY);
		return;
	}

	w->runtime_ns += on_cpu_ns;

	u64 elapsed = now > w->window_start_ns ? now - w->window_start_ns : 0;
	if (elapsed < CPU_SAMPLE_WINDOW_NS)
		return;

	struct cpu_quota *q = bpf_map_lookup_elem(&cgroup_cpu_quota, &cgid);
	if (q && q->quota_us > 0 && elapsed > 0) {
		u64 numerator = w->runtime_ns * q->period_us * 100ULL;
		u64 denominator = elapsed * q->quota_us;
		u32 util = denominator ? (u32)(numerator / denominator) : 0;
		if (util > 100)
			util = 100;
		emit_resource_alert(cgid, RESOURCE_CPU, util, q->quota_us, w->runtime_ns);
	}

	w->window_start_ns = now;
	w->runtime_ns = 0;
}

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

	if (next_pid > 0) {
		u64 *out_ts = bpf_map_lookup_elem(&sched_out_ts, &next_pid);
		if (out_ts) {
			u64 blocked = now > *out_ts ? now - *out_ts : 0;
			bpf_map_delete_elem(&sched_out_ts, &next_pid);
			if (blocked > MIN_LATENCY_NS) {
				bpf_map_update_elem(&sched_pending_blocked, &next_pid, &blocked, BPF_ANY);
			}
		}
		bpf_map_update_elem(&sched_in_ts, &next_pid, &now, BPF_ANY);
	}

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

		u64 *in_ts = bpf_map_lookup_elem(&sched_in_ts, &prev_pid);
		if (in_ts) {
			u64 on_cpu = now > *in_ts ? now - *in_ts : 0;
			bpf_map_delete_elem(&sched_in_ts, &prev_pid);
			if (on_cpu > 0) {
				cpu_sample_accumulate(ctx, on_cpu, now);
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