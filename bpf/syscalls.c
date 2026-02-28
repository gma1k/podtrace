// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

SEC("kprobe/do_execveat_common")
int kprobe_do_execveat_common(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);

	const char *filename = (const char *)PT_REGS_PARM2(ctx);
	if (filename) {
		char buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(buf, sizeof(buf), filename);
		bpf_map_update_elem(&syscall_paths, &key, buf, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/do_execveat_common")
int kretprobe_do_execveat_common(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}

	u64 latency = calc_latency(*start_ts);
	s64 ret = PT_REGS_RC(ctx);

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_EXEC;
	e->latency_ns = latency;
	e->error = ret < 0 ? ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;

	char *path = bpf_map_lookup_elem(&syscall_paths, &key);
	if (path) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), path);
		bpf_map_delete_elem(&syscall_paths, &key);
	} else {
		e->target[0] = '\0';
	}

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("tp/sched/sched_process_fork")
int tracepoint_sched_process_fork(void *ctx) {
	struct {
		unsigned short common_type;
		unsigned char common_flags;
		unsigned char common_preempt_count;
		int common_pid;
		char parent_comm[16];
		s32 parent_pid;
		char child_comm[16];
		s32 child_pid;
		int child_prio;
	} *args = (typeof(args))ctx;

	u32 child_pid = args->child_pid;
	if (child_pid == 0) {
		return 0;
	}

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = child_pid;
	e->type = EVENT_FORK;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;

	bpf_probe_read_kernel_str(e->target, sizeof(e->target), args->child_comm);

	capture_user_stack(ctx, child_pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

SEC("kprobe/do_sys_openat2")
int kprobe_do_sys_openat2(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);

	const char *filename = (const char *)PT_REGS_PARM2(ctx);
	if (filename) {
		char buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(buf, sizeof(buf), filename);
		bpf_map_update_elem(&syscall_paths, &key, buf, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/do_sys_openat2")
int kretprobe_do_sys_openat2(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}

	u64 latency = calc_latency(*start_ts);
	s64 ret = PT_REGS_RC(ctx);

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_OPEN;
	e->latency_ns = latency;
	e->error = ret < 0 ? ret : 0;
	e->bytes = ret >= 0 ? (u64)ret : 0;
	e->tcp_state = 0;

	char *path = bpf_map_lookup_elem(&syscall_paths, &key);
	if (path) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), path);
		bpf_map_delete_elem(&syscall_paths, &key);
	} else {
		e->target[0] = '\0';
	}

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);

#ifdef PODTRACE_VMLINUX_FROM_BTF
	/* PARM3 = struct dentry * of the entry being unlinked */
	struct dentry *de = (struct dentry *)PT_REGS_PARM3(ctx);
	if (de) {
		char buf[MAX_STRING_LEN] = {};
		const unsigned char *name = BPF_CORE_READ(de, d_name.name);
		if (name) {
			bpf_probe_read_kernel_str(buf, sizeof(buf), name);
			bpf_map_update_elem(&syscall_paths, &key, buf, BPF_ANY);
		}
	}
#endif
	return 0;
}

SEC("kretprobe/vfs_unlink")
int kretprobe_vfs_unlink(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts)
		return 0;

	u64 latency = calc_latency(*start_ts);
	s64 ret = PT_REGS_RC(ctx);

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_UNLINK;
	e->latency_ns = latency;
	e->error = ret < 0 ? (s32)ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;

	char *path = bpf_map_lookup_elem(&syscall_paths, &key);
	if (path) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), path);
		bpf_map_delete_elem(&syscall_paths, &key);
	} else {
		e->target[0] = '\0';
	}

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

/*
 * vfs_rename kprobe: signature varies across kernel versions.
 * Pre-6.3: vfs_rename(old_dir, old_dentry, new_dir, new_dentry, ...) — PARM2 and PARM4.
 * 6.3+:    vfs_rename(struct renamedata *) — single struct pointer.
 * This probe targets the pre-6.3 layout and is optional.
 */
SEC("kprobe/vfs_rename")
int kprobe_vfs_rename(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);

#ifdef PODTRACE_VMLINUX_FROM_BTF
	struct dentry *old_de = (struct dentry *)PT_REGS_PARM2(ctx);
	struct dentry *new_de = (struct dentry *)PT_REGS_PARM4(ctx);
	if (old_de && new_de) {
		char buf[MAX_STRING_LEN] = {};
		const unsigned char *old_name = BPF_CORE_READ(old_de, d_name.name);
		const unsigned char *new_name = BPF_CORE_READ(new_de, d_name.name);
		u32 idx = 0;
		u32 max_idx = MAX_STRING_LEN - 1;
		if (old_name) {
			int n = bpf_probe_read_kernel_str(buf, sizeof(buf) - 1, old_name);
			if (n > 1) idx = (u32)(n - 1);
		}
		if (idx < max_idx) buf[idx++] = '>';
		if (new_name && idx < max_idx)
			bpf_probe_read_kernel_str(buf + idx, max_idx - idx, new_name);
		buf[max_idx] = '\0';
		bpf_map_update_elem(&syscall_paths, &key, buf, BPF_ANY);
	}
#endif
	return 0;
}

SEC("kretprobe/vfs_rename")
int kretprobe_vfs_rename(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts)
		return 0;

	u64 latency = calc_latency(*start_ts);
	s64 ret = PT_REGS_RC(ctx);

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_RENAME;
	e->latency_ns = latency;
	e->error = ret < 0 ? (s32)ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;

	char *path = bpf_map_lookup_elem(&syscall_paths, &key);
	if (path) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), path);
		bpf_map_delete_elem(&syscall_paths, &key);
	} else {
		e->target[0] = '\0';
	}

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/__close_fd")
int kprobe___close_fd(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	unsigned int fd = (unsigned int)PT_REGS_PARM2(ctx);

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_CLOSE;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = (u64)fd;
	e->tcp_state = 0;
	e->target[0] = '\0';

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}
