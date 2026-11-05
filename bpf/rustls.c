// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"


#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define RUSTLS_BUF(ctx)       ((void *)(ctx)->si)
#define RUSTLS_LEN(ctx)       ((u64)(ctx)->dx)
#define RUSTLS_RET_OK(ctx)    ((ctx)->ax == 0)
#define RUSTLS_RET_COUNT(ctx) ((u64)(ctx)->dx)
#define RUSTLS_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define RUSTLS_BUF(ctx)       ((void *)(ctx)->regs[1])
#define RUSTLS_LEN(ctx)       ((u64)(ctx)->regs[2])
#define RUSTLS_RET_OK(ctx)    ((ctx)->regs[0] == 0)
#define RUSTLS_RET_COUNT(ctx) ((u64)(ctx)->regs[1])
#define RUSTLS_SUPPORTED 1
#endif


#ifdef RUSTLS_SUPPORTED

#define RUSTLS_PEEK 16
#define RUSTLS_WRITE_STALE_NS 1000000000ULL

static __always_inline u64 rustls_conn_key(u32 dir)
{
	u32 prefer = (dir == H2_DIR_EGRESS) ? PAIR_TCP_SENDMSG : PAIR_TCP_RECVMSG;
	struct tcp_peer *p = lookup_tcp_peer(prefer);
	if (!p || !p->sk)
		return 0;
	return process_scoped_id(p->sk);
}

static __always_inline u64 rustls_thread_key(void)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return get_key(pid, tid);
}

static __always_inline void rustls_dispatch(void *ctx, void *base, u64 len,
					    u64 conn, u32 dir)
{
	if (!base || len == 0 || conn == 0)
		return;
	if (oncpu_is_enabled())
		oncpu_note_thread_conn(conn);
	u8 peek[RUSTLS_PEEK] = {};
	u32 plen = len < sizeof(peek) ? (u32)len : sizeof(peek);
	if (bpf_probe_read_user(peek, plen, base) != 0)
		return;

	u8 transport = HTTP_TRANSPORT_TLS | (dir == H2_DIR_EGRESS ? 0 : HTTP_INBOUND);
	if (peek[0] == 'H' && peek[1] == 'T' && peek[2] == 'T' && peek[3] == 'P' &&
	    peek[4] == '/' && peek[5] == '1' && peek[6] == '.')
		http_emit_response(ctx, base, len, transport, conn);
	else if (http_method_len(peek) > 0)
		http_emit_request(ctx, base, len, transport, conn);
	else
		h2_emit_frames(base, len, conn, dir, HTTP_TRANSPORT_H2_TLS);
}

static __always_inline void rustls_dispatch_write(void *ctx, u64 key, u64 conn)
{
	struct rustls_write_state *st = bpf_map_lookup_elem(&rustls_write_args, &key);
	if (!st || !st->len)
		return;
	u64 buf = st->buf;
	u64 len = st->len;
	u64 ts = st->ts;
	bpf_map_delete_elem(&rustls_write_args, &key);
	if (bpf_ktime_get_ns() - ts > RUSTLS_WRITE_STALE_NS)
		return;
	rustls_dispatch(ctx, (void *)buf, len, conn, H2_DIR_EGRESS);
}

__noinline int rustls_flush_pending(struct pt_regs *ctx, u64 sk)
{
	if (!ctx || !sk)
		return 0;
	rustls_dispatch_write(ctx, rustls_thread_key(), process_scoped_id(sk));
	return 0;
}

SEC("uprobe/rustls_write")
int uprobe_rustls_write(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u64 key = rustls_thread_key();
	rustls_dispatch_write(ctx, key, rustls_conn_key(H2_DIR_EGRESS));
	struct rustls_write_state st = { .buf = (u64)RUSTLS_BUF(ctx) };
	bpf_map_update_elem(&rustls_write_args, &key, &st, BPF_ANY);
	return 0;
}

SEC("uretprobe/rustls_write")
int uretprobe_rustls_write(struct pt_regs *ctx)
{
	u64 key = rustls_thread_key();
	struct rustls_write_state *st = bpf_map_lookup_elem(&rustls_write_args, &key);
	if (!st || st->len)
		return 0;
	u64 count = RUSTLS_RET_COUNT(ctx);
	if (!RUSTLS_RET_OK(ctx) || count == 0 || count >= MAX_BYTES_THRESHOLD) {
		bpf_map_delete_elem(&rustls_write_args, &key);
		return 0;
	}
	st->len = count;
	st->ts = bpf_ktime_get_ns();
	return 0;
}

SEC("uprobe/rustls_read")
int uprobe_rustls_read(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u64 key = rustls_thread_key();
	struct ssl_read_state st = {
		.buf = (u64)RUSTLS_BUF(ctx),
		.conn = rustls_conn_key(H2_DIR_INGRESS),
	};
	bpf_map_update_elem(&rustls_read_args, &key, &st, BPF_ANY);
	return 0;
}

SEC("uretprobe/rustls_read")
int uretprobe_rustls_read(struct pt_regs *ctx)
{
	u64 key = rustls_thread_key();
	struct ssl_read_state *st = bpf_map_lookup_elem(&rustls_read_args, &key);
	if (!st)
		return 0;
	void *base = (void *)st->buf;
	u64 conn = st->conn;
	bpf_map_delete_elem(&rustls_read_args, &key);

	if (!RUSTLS_RET_OK(ctx))
		return 0;
	u64 count = RUSTLS_RET_COUNT(ctx);
	if (count == 0 || count >= MAX_BYTES_THRESHOLD)
		return 0;
	rustls_dispatch(ctx, base, count, conn, H2_DIR_INGRESS);
	return 0;
}

#else

__noinline int rustls_flush_pending(struct pt_regs *ctx, u64 sk) { return 0; }

SEC("uprobe/rustls_write")
int uprobe_rustls_write(struct pt_regs *ctx) { return 0; }

SEC("uretprobe/rustls_write")
int uretprobe_rustls_write(struct pt_regs *ctx) { return 0; }

SEC("uprobe/rustls_read")
int uprobe_rustls_read(struct pt_regs *ctx) { return 0; }

SEC("uretprobe/rustls_read")
int uretprobe_rustls_read(struct pt_regs *ctx) { return 0; }

#endif
