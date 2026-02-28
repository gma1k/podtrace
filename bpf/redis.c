// SPDX-License-Identifier: GPL-2.0
/*
 * Redis tracing via hiredis library uprobes.
 *
 * Hooks:
 *   uprobe/redisCommand       — int redisCommand(redisContext *c, const char *format, ...)
 *   uretprobe/redisCommand
 *   uprobe/redisCommandArgv   — void *redisCommandArgv(redisContext *c, int argc,
 *                                   const char **argv, const size_t *argvlen)
 *   uretprobe/redisCommandArgv
 *
 * Field mapping (event struct):
 *   target  = server IP:port (from socket_conns if available, else empty)
 *   details = command name (e.g. "SET", "GET", "HGET")
 *   bytes   = 0 (response size not available without reading reply object)
 *   error   = return value (NULL pointer = error in hiredis)
 *   latency_ns = time from entry to return
 */

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

/* Store the command name from the format string PARM2.
 * Truncates at the first space or '%' (format verbs follow the command). */
static __always_inline void redis_store_cmd(u64 key, const char *format_ptr, u64 ts)
{
	char buf[MAX_STRING_LEN] = {};
	bpf_probe_read_user_str(buf, sizeof(buf), format_ptr);

	/* Truncate at first space or '%' — format is "CMD arg1 %s ..." */
	u32 i;
	for (i = 0; i < MAX_STRING_LEN; i++) {
		if (buf[i] == ' ' || buf[i] == '%' || buf[i] == '\0') {
			buf[i] = '\0';
			break;
		}
	}

	bpf_map_update_elem(&redis_cmds, &key, buf, BPF_ANY);
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
}

/* Emit the EVENT_REDIS_CMD event from a uretprobe context. */
static __always_inline int redis_emit(struct pt_regs *ctx, u64 key, u32 pid, u32 tid)
{
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts)
		return 0;

	u64 latency = calc_latency(*start_ts);

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		bpf_map_delete_elem(&redis_cmds, &key);
		return 0;
	}

	e->timestamp  = bpf_ktime_get_ns();
	e->pid        = pid;
	e->type       = EVENT_REDIS_CMD;
	e->latency_ns = latency;
	/* NULL return = error (hiredis returns NULL on failure) */
	e->error      = PT_REGS_RC(ctx) == 0 ? -1 : 0;
	e->bytes      = 0;
	e->tcp_state  = 0;

	/* Command name */
	char *cmd_ptr = bpf_map_lookup_elem(&redis_cmds, &key);
	if (cmd_ptr)
		bpf_probe_read_kernel_str(e->details, sizeof(e->details), cmd_ptr);
	else
		e->details[0] = '\0';

	/* Server target (populated by tcp_connect probes into socket_conns) */
	char *conn_ptr = bpf_map_lookup_elem(&socket_conns, &key);
	if (conn_ptr)
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), conn_ptr);
	else
		e->target[0] = '\0';

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);

	bpf_map_delete_elem(&start_times, &key);
	bpf_map_delete_elem(&redis_cmds, &key);
	return 0;
}

/* uprobe/redisCommand — PARM2 = const char *format */
SEC("uprobe/redisCommand")
int uprobe_redisCommand(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts  = bpf_ktime_get_ns();

	const char *fmt = (const char *)PT_REGS_PARM2(ctx);
	if (fmt)
		redis_store_cmd(key, fmt, ts);
	return 0;
}

SEC("uretprobe/redisCommand")
int uretprobe_redisCommand(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return redis_emit(ctx, get_key(pid, tid), pid, tid);
}

/* uprobe/redisCommandArgv — PARM3 = const char **argv, argv[0] = command */
SEC("uprobe/redisCommandArgv")
int uprobe_redisCommandArgv(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts  = bpf_ktime_get_ns();

	/* PARM3 = const char **argv; argv[0] is the command name */
	const char **argv = (const char **)PT_REGS_PARM3(ctx);
	if (!argv)
		return 0;

	/* First dereference: read the argv[0] pointer from user space */
	const char *cmd_ptr = NULL;
	if (bpf_probe_read_user(&cmd_ptr, sizeof(cmd_ptr), argv) != 0 || !cmd_ptr)
		return 0;

	char buf[MAX_STRING_LEN] = {};
	bpf_probe_read_user_str(buf, sizeof(buf), cmd_ptr);

	bpf_map_update_elem(&redis_cmds, &key, buf, BPF_ANY);
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/redisCommandArgv")
int uretprobe_redisCommandArgv(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return redis_emit(ctx, get_key(pid, tid), pid, tid);
}
