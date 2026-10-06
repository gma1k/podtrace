// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "filesystem.h"

static __always_inline int fs_enter(u32 pair, struct file *file)
{
	if (!fs_traced() || !fs_is_regular(file))
		return 0;
	struct pair_key key = make_pair_key(pair);
	struct fs_inflight in = {
		.start_ns = bpf_ktime_get_ns(),
		.file = (u64)file,
	};
	bpf_map_update_elem(&fs_inflight, &key, &in, BPF_ANY);
	return 0;
}

static __always_inline int fs_finish(void *ctx, u32 type, u64 start_ns, struct file *file,
				     s64 ret, int has_bytes)
{
	u64 latency = calc_latency(start_ns);
	u64 bytes = 0;
	if (has_bytes && ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD)
		bytes = (u64)ret;
	s32 err = ret < 0 ? (s32)ret : 0;

	int recorded = fs_count(type, latency, bytes, err);
	if (latency < MIN_LATENCY_NS)
		return 0;

	struct event *e = get_event_buf();
	if (!e)
		return 0;
	e->timestamp = bpf_ktime_get_ns();
	e->pid = agent_ns_tgid();
	e->type = type;
	e->latency_ns = latency;
	e->error = err;
	e->bytes = bytes;
	e->tcp_state = 0;
	get_path_str_from_file(file, e->target, sizeof(e->target));
	fs_emit(ctx, e, recorded);
	return 0;
}

static __always_inline int fs_exit(void *ctx, u32 pair, u32 type, s64 ret, int has_bytes)
{
	struct pair_key key = make_pair_key(pair);
	struct fs_inflight *in = bpf_map_lookup_elem(&fs_inflight, &key);
	if (!in)
		return 0;
	u64 start_ns = in->start_ns;
	struct file *file = (struct file *)in->file;
	bpf_map_delete_elem(&fs_inflight, &key);
	return fs_finish(ctx, type, start_ns, file, ret, has_bytes);
}

static __always_inline int fs_task_enter(u32 slot, struct file *file)
{
	if (!fs_traced() || !fs_is_regular(file))
		return 0;
	struct fs_task_starts *st = bpf_task_storage_get(&fs_task_inflight,
		bpf_get_current_task_btf(), 0, 1 /* BPF_LOCAL_STORAGE_GET_F_CREATE */);
	if (st && slot < FS_TASK_SLOTS)
		st->start_ns[slot] = bpf_ktime_get_ns();
	return 0;
}

static __always_inline int fs_task_exit(void *ctx, u32 slot, u32 type, struct file *file,
					s64 ret, int has_bytes)
{
	struct fs_task_starts *st = bpf_task_storage_get(&fs_task_inflight,
		bpf_get_current_task_btf(), 0, 0);
	if (!st || slot >= FS_TASK_SLOTS)
		return 0;
	u64 start_ns = st->start_ns[slot];
	if (!start_ns)
		return 0;
	st->start_ns[slot] = 0;
	return fs_finish(ctx, type, start_ns, file, ret, has_bytes);
}

SEC("kprobe/vfs_read")
int kprobe_vfs_read(struct pt_regs *ctx)
{
	return fs_enter(PAIR_VFS_READ, (struct file *)PT_REGS_PARM1(ctx));
}

SEC("kretprobe/vfs_read")
int kretprobe_vfs_read(struct pt_regs *ctx)
{
	return fs_exit(ctx, PAIR_VFS_READ, EVENT_READ, PT_REGS_RC(ctx), 1);
}

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx)
{
	return fs_enter(PAIR_VFS_WRITE, (struct file *)PT_REGS_PARM1(ctx));
}

SEC("kretprobe/vfs_write")
int kretprobe_vfs_write(struct pt_regs *ctx)
{
	return fs_exit(ctx, PAIR_VFS_WRITE, EVENT_WRITE, PT_REGS_RC(ctx), 1);
}

SEC("fentry/vfs_read")
int BPF_PROG(fentry_vfs_read, struct file *file)
{
	return fs_task_enter(FS_TASK_SLOT_READ, file);
}

SEC("fexit/vfs_read")
int BPF_PROG(fexit_vfs_read, struct file *file, void *buf, u64 count, void *pos, s64 ret)
{
	return fs_task_exit(ctx, FS_TASK_SLOT_READ, EVENT_READ, file, ret, 1);
}

SEC("fentry/vfs_write")
int BPF_PROG(fentry_vfs_write, struct file *file)
{
	return fs_task_enter(FS_TASK_SLOT_WRITE, file);
}

SEC("fexit/vfs_write")
int BPF_PROG(fexit_vfs_write, struct file *file, void *buf, u64 count, void *pos, s64 ret)
{
	return fs_task_exit(ctx, FS_TASK_SLOT_WRITE, EVENT_WRITE, file, ret, 1);
}

struct fs_sys_enter {
	u64 common;
	s64 syscall_nr;
	u64 fd;
};

struct fs_sys_exit {
	u64 common;
	s64 syscall_nr;
	s64 ret;
};

SEC("tp/syscalls/sys_enter_fsync")
int tracepoint_sys_enter_fsync(struct fs_sys_enter *ctx)
{
	return fs_enter(PAIR_VFS_FSYNC, fs_file_of_fd((unsigned int)ctx->fd));
}

SEC("tp/syscalls/sys_exit_fsync")
int tracepoint_sys_exit_fsync(struct fs_sys_exit *ctx)
{
	return fs_exit(ctx, PAIR_VFS_FSYNC, EVENT_FSYNC, ctx->ret, 0);
}

SEC("tp/syscalls/sys_enter_fdatasync")
int tracepoint_sys_enter_fdatasync(struct fs_sys_enter *ctx)
{
	return fs_enter(PAIR_VFS_FSYNC, fs_file_of_fd((unsigned int)ctx->fd));
}

SEC("tp/syscalls/sys_exit_fdatasync")
int tracepoint_sys_exit_fdatasync(struct fs_sys_exit *ctx)
{
	return fs_exit(ctx, PAIR_VFS_FSYNC, EVENT_FSYNC, ctx->ret, 0);
}
