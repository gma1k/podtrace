// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

struct sched_process_exec_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	unsigned int filename_loc;
	int pid;
	int old_pid;
};
_Static_assert(__builtin_offsetof(struct sched_process_exec_args, filename_loc) == 8, "sched_process_exec: filename __data_loc must be at offset 8");
_Static_assert(__builtin_offsetof(struct sched_process_exec_args, pid) == 12, "sched_process_exec: pid must be at offset 12");

SEC("tp/sched/sched_process_exec")
int tracepoint_sched_process_exec(void *ctx) {
	struct sched_process_exec_args args_local = {};
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->type = EVENT_EXEC;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';

	unsigned short name_off = (unsigned short)(args_local.filename_loc & 0xffff);
	bpf_probe_read_kernel_str(e->target, sizeof(e->target), (char *)ctx + name_off);

	capture_user_stack(ctx, e->pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
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
	} args_local = {};
	bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx);

	u32 child_pid = args_local.child_pid;
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
	__builtin_memcpy(e->comm, args_local.child_comm, sizeof(e->comm));

	bpf_probe_read_kernel_str(e->target, sizeof(e->target), args_local.child_comm);

	capture_user_stack(ctx, child_pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

SEC("kprobe/do_sys_openat2")
int kprobe_do_sys_openat2(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_OPENAT);
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
	struct pair_key key = make_pair_key(PAIR_OPENAT);
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
	struct pair_key key = make_pair_key(PAIR_VFS_UNLINK);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);

#ifdef PODTRACE_VMLINUX_FROM_BTF
	struct dentry *de_parm2 = (struct dentry *)PT_REGS_PARM2(ctx);
	barrier_var(de_parm2);
	struct dentry *de_parm3 = (struct dentry *)PT_REGS_PARM3(ctx);
	barrier_var(de_parm3);
	struct dentry *de = bpf_core_type_exists(struct renamedata) ? de_parm3 : de_parm2;
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
	struct pair_key key = make_pair_key(PAIR_VFS_UNLINK);
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

SEC("kprobe/vfs_rename")
int kprobe_vfs_rename(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_VFS_RENAME);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);

#ifdef PODTRACE_VMLINUX_FROM_BTF
	struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1(ctx);
	barrier_var(rd);
	struct dentry *old_parm2 = (struct dentry *)PT_REGS_PARM2(ctx);
	barrier_var(old_parm2);
	struct dentry *new_parm4 = (struct dentry *)PT_REGS_PARM4(ctx);
	barrier_var(new_parm4);
	struct dentry *old_de;
	struct dentry *new_de;
	if (bpf_core_type_exists(struct renamedata)) {
		old_de = (struct dentry *)BPF_CORE_READ(rd, old_dentry);
		new_de = (struct dentry *)BPF_CORE_READ(rd, new_dentry);
	} else {
		old_de = old_parm2;
		new_de = new_parm4;
	}
	if (old_de && new_de) {
		char buf[MAX_STRING_LEN] = {};
		const unsigned char *old_name = BPF_CORE_READ(old_de, d_name.name);
		const unsigned char *new_name = BPF_CORE_READ(new_de, d_name.name);
		if (old_name)
			bpf_probe_read_kernel_str(buf, MAX_STRING_LEN / 2 - 1, old_name);
		buf[MAX_STRING_LEN / 2 - 1] = '>';
		if (new_name)
			bpf_probe_read_kernel_str(buf + MAX_STRING_LEN / 2, MAX_STRING_LEN / 2, new_name);
		bpf_map_update_elem(&syscall_paths, &key, buf, BPF_ANY);
	}
#endif
	return 0;
}

SEC("kretprobe/vfs_rename")
int kretprobe_vfs_rename(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_VFS_RENAME);
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
		bpf_probe_read_kernel(e->target, sizeof(e->target), path);
		bpf_map_delete_elem(&syscall_paths, &key);
	} else {
		e->target[0] = '\0';
	}

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/close_fd")
int kprobe_close_fd(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);

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
