// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"
#ifdef PODTRACE_VMLINUX_FROM_BTF

static __always_inline int http_method_len(const u8 *b)
{
	if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ')
		return 3;
	if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ')
		return 3;
	if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ')
		return 4;
	if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ')
		return 4;
	if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H' &&
	    b[5] == ' ')
		return 5;
	if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' &&
	    b[5] == 'E' && b[6] == ' ')
		return 6;
	if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' &&
	    b[5] == 'N' && b[6] == 'S' && b[7] == ' ')
		return 7;
	return 0;
}

static __always_inline int http_should_trace(void)
{
	u32 zero = 0;
	u32 *enabled = bpf_map_lookup_elem(&cgroup_filter_enabled, &zero);
	if (enabled && *enabled) {
		u64 cgid = bpf_get_current_cgroup_id();
		if (!bpf_map_lookup_elem(&target_cgroup_ids, &cgid))
			return 0;
	}
	return 1;
}

struct tp_scan_ctx {
	u32 rlen;
	int pos;
};

static long tp_scan_cb(u32 i, void *vctx)
{
	struct tp_scan_ctx *c = (struct tp_scan_ctx *)vctx;
	if (i + 16 >= HTTP_SCAN_BUF_SIZE || i >= c->rlen)
		return 1;
	u32 zero = 0;
	char *buf = bpf_map_lookup_elem(&http_scan_buf, &zero);
	if (!buf)
		return 1;
	const char needle[] = "traceparent:";
	u32 diff = 0;
	u32 j;
#pragma unroll
	for (j = 0; j < 12; j++)
		diff |= (u32)(((u8)buf[(i + j) & (HTTP_SCAN_BUF_SIZE - 1)] | 0x20) ^ (u8)needle[j]);
	if (diff == 0) {
		c->pos = (int)i;
		return 1;
	}
	return 0;
}

static __noinline void http_capture_traceparent(void *base, u64 avail, char *out)
{
	out[0] = '\0';
	if (!base)
		return;
	u32 zero = 0;
	char *buf = bpf_map_lookup_elem(&http_scan_buf, &zero);
	if (!buf)
		return;
	u32 rlen = (avail < HTTP_SCAN_BUF_SIZE) ? (u32)avail : HTTP_SCAN_BUF_SIZE;
	if (rlen < 32)
		return;
	if (bpf_probe_read_user(buf, rlen, base) != 0)
		return;

	struct tp_scan_ctx sc = {.rlen = rlen, .pos = -1};
	bpf_loop(HTTP_SCAN_BUF_SIZE, tp_scan_cb, &sc, 0);
	if (sc.pos < 0)
		return;

	u32 v = (u32)sc.pos + 12;
	if (v < HTTP_SCAN_BUF_SIZE && buf[v & (HTTP_SCAN_BUF_SIZE - 1)] == ' ')
		v++;

	if (v + W3C_TRACEPARENT_LEN > rlen)
		return;

	__builtin_memcpy(out, "traceparent: ", 13);
	if (bpf_probe_read_user(out + 13, W3C_TRACEPARENT_LEN, (char *)base + v) != 0) {
		out[0] = '\0';
		return;
	}
	out[13 + W3C_TRACEPARENT_LEN] = '\0';
}

static __noinline void http_emit_request(void *ctx, void *base, u64 avail,
					 u8 transport, u64 conn)
{
	if (!base || avail < HTTP_MIN_REQUEST_LEN)
		return;

	u32 zero = 0;
	char *buf = bpf_map_lookup_elem(&http_scan_buf, &zero);
	if (!buf)
		return;
	u32 read_len = (avail < HTTP_INSPECT_LEN) ? (u32)avail : HTTP_INSPECT_LEN;
	if (bpf_probe_read_user(buf, read_len, base) != 0)
		return;

	if (http_method_len((const u8 *)buf) == 0)
		return;

	struct http_req req = {};
	req.start_ns = bpf_ktime_get_ns();
	u32 p = 0;
	int spaces = 0;
	u32 i;
	for (i = 0; i < HTTP_INSPECT_LEN && i < read_len && p < MAX_STRING_LEN - 1; i++) {
		u8 c = (u8)buf[i & (HTTP_SCAN_BUF_SIZE - 1)];
		if (c == '\r' || c == '\n' || c == 0)
			break;
		if (c == ' ') {
			spaces++;
			if (spaces == 2)
				break;
		}
		req.endpoint[p++] = c;
	}
	if (p == 0)
		return;
	req.endpoint[p & (MAX_STRING_LEN - 1)] = '\0';

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 now = req.start_ns;

	bpf_map_update_elem(&http_reqs, &conn, &req, BPF_ANY);

	struct event *e = get_event_buf();
	if (e) {
		e->timestamp = now;
		e->pid = pid;
		e->type = EVENT_HTTP_REQ;
		e->latency_ns = 0;
		e->error = 0;
		e->bytes = 0;
		e->tcp_state = transport;
		e->correlation_id = now;
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), req.endpoint);
		http_capture_traceparent(base, avail, e->details);
		fill_event_peer(e);
		capture_user_stack(ctx, pid, tid, e);
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	}
}

static __noinline void http_emit_response(void *ctx, void *base, u64 len,
					  u8 transport, u64 conn)
{
	if (!base || len == 0 || len >= MAX_BYTES_THRESHOLD)
		return;

	u32 read_len = (u32)len;
	if (read_len > HTTP_INSPECT_LEN)
		read_len = HTTP_INSPECT_LEN;

	u8 buf[HTTP_INSPECT_LEN] = {};
	if (bpf_probe_read_user(buf, read_len, base) != 0)
		return;

	if (!(buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' &&
	      buf[4] == '/' && buf[5] == '1' && buf[6] == '.'))
		return;

	char status[4] = {};
	u32 si = 0;
	int seen_space = 0;
	u32 i;
	for (i = 0; i < HTTP_INSPECT_LEN && si < 3; i++) {
		u8 c = buf[i];
		if (!seen_space) {
			if (c == ' ')
				seen_space = 1;
			continue;
		}
		if (c < '0' || c > '9')
			break;
		status[si++] = c;
	}
	if (si == 0)
		return;
	status[si] = '\0';

	if (si == 3 && status[0] == '1')
		return;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();

	struct http_req *req = bpf_map_lookup_elem(&http_reqs, &conn);
	if (!req)
		return;

	u64 latency_ns = calc_latency(req->start_ns);
	s32 status_num = (status[0] - '0') * 100 + (status[1] - '0') * 10 +
			 (status[2] - '0');

	struct event *e = get_event_buf();
	if (e) {
		e->timestamp = bpf_ktime_get_ns();
		e->pid = pid;
		e->type = EVENT_HTTP_RESP;
		e->latency_ns = latency_ns;
		e->error = status_num >= 500 ? status_num : 0;
		e->bytes = len;
		e->tcp_state = transport;
		e->correlation_id = req->start_ns;
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), req->endpoint);
		bpf_probe_read_kernel_str(e->details, sizeof(e->details), status);
		fill_event_peer(e);
		capture_user_stack(ctx, pid, tid, e);
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	}
	bpf_map_delete_elem(&http_reqs, &conn);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_http_tcp_sendmsg(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u64 sk = (u64)PT_REGS_PARM1(ctx);
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	http_emit_request(ctx, base, avail, HTTP_TRANSPORT_PLAINTEXT, sk);
	http_emit_response(ctx, base, avail, HTTP_TRANSPORT_PLAINTEXT, sk);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_http_tcp_recvmsg(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	if (!base)
		return 0;

	struct ssl_read_state st = { .buf = (u64)base, .conn = (u64)PT_REGS_PARM1(ctx) };
	bpf_map_update_elem(&http_recv_base, &key, &st, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_http_tcp_recvmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	struct ssl_read_state *st = bpf_map_lookup_elem(&http_recv_base, &key);
	if (!st)
		return 0;
	void *base = (void *)st->buf;
	u64 sk = st->conn;
	bpf_map_delete_elem(&http_recv_base, &key);

	s32 ret = (s32)PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;
	http_emit_response(ctx, base, (u64)ret, HTTP_TRANSPORT_PLAINTEXT, sk);
	http_emit_request(ctx, base, (u64)ret, HTTP_TRANSPORT_PLAINTEXT, sk);
	return 0;
}

static __always_inline void h2_emit_frames(void *base, u64 avail, u64 conn,
					   u32 dir, u8 transport);

#define SSL_TLS_PEEK 16

SEC("uprobe/SSL_write")
int uprobe_SSL_write(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	void *ssl = (void *)PT_REGS_PARM1(ctx);
	void *base = (void *)PT_REGS_PARM2(ctx);
	u64 num = (u64)(s64)PT_REGS_PARM3(ctx);
	if (!base || num == 0)
		return 0;

	u8 peek[SSL_TLS_PEEK] = {};
	u32 plen = num < sizeof(peek) ? (u32)num : sizeof(peek);
	if (bpf_probe_read_user(peek, plen, base) != 0)
		return 0;

	if (http_method_len(peek) > 0)
		http_emit_request(ctx, base, num, HTTP_TRANSPORT_TLS, (u64)ssl);
	else if (peek[0] == 'H' && peek[1] == 'T' && peek[2] == 'T' && peek[3] == 'P' &&
		 peek[4] == '/' && peek[5] == '1' && peek[6] == '.')
		http_emit_response(ctx, base, num, HTTP_TRANSPORT_TLS, (u64)ssl);
	else
		h2_emit_frames(base, num, (u64)ssl, H2_DIR_EGRESS,
			       HTTP_TRANSPORT_H2_TLS);
	return 0;
}

SEC("uprobe/SSL_read")
int uprobe_SSL_read(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	struct ssl_read_state st = {
		.buf = (u64)PT_REGS_PARM2(ctx),
		.conn = (u64)PT_REGS_PARM1(ctx),
	};
	bpf_map_update_elem(&ssl_read_args, &key, &st, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	struct ssl_read_state *st = bpf_map_lookup_elem(&ssl_read_args, &key);
	if (!st)
		return 0;
	void *base = (void *)st->buf;
	u64 conn = st->conn;
	bpf_map_delete_elem(&ssl_read_args, &key);
	s64 ret = PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;

	u8 peek[SSL_TLS_PEEK] = {};
	u32 plen = (u64)ret < sizeof(peek) ? (u32)ret : sizeof(peek);
	if (bpf_probe_read_user(peek, plen, base) != 0)
		return 0;

	if (peek[0] == 'H' && peek[1] == 'T' && peek[2] == 'T' && peek[3] == 'P' &&
	    peek[4] == '/' && peek[5] == '1' && peek[6] == '.')
		http_emit_response(ctx, base, (u64)ret, HTTP_TRANSPORT_TLS, conn);
	else if (http_method_len(peek) > 0)
		http_emit_request(ctx, base, (u64)ret, HTTP_TRANSPORT_TLS, conn);
	else
		h2_emit_frames(base, (u64)ret, conn, H2_DIR_INGRESS,
			       HTTP_TRANSPORT_H2_TLS);
	return 0;
}

SEC("uprobe/gnutls_record_send")
int uprobe_gnutls_record_send(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	void *session = (void *)PT_REGS_PARM1(ctx);
	void *base = (void *)PT_REGS_PARM2(ctx);
	u64 num = (u64)PT_REGS_PARM3(ctx);
	http_emit_request(ctx, base, num, HTTP_TRANSPORT_TLS, (u64)session);
	http_emit_response(ctx, base, num, HTTP_TRANSPORT_TLS, (u64)session);
	return 0;
}

SEC("uprobe/gnutls_record_recv")
int uprobe_gnutls_record_recv(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	struct ssl_read_state st = {
		.buf = (u64)PT_REGS_PARM2(ctx),
		.conn = (u64)PT_REGS_PARM1(ctx),
	};
	bpf_map_update_elem(&ssl_read_args, &key, &st, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_record_recv")
int uretprobe_gnutls_record_recv(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	struct ssl_read_state *st = bpf_map_lookup_elem(&ssl_read_args, &key);
	if (!st)
		return 0;
	void *base = (void *)st->buf;
	u64 conn = st->conn;
	bpf_map_delete_elem(&ssl_read_args, &key);
	s64 ret = PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;
	http_emit_response(ctx, base, (u64)ret, HTTP_TRANSPORT_TLS, conn);
	http_emit_request(ctx, base, (u64)ret, HTTP_TRANSPORT_TLS, conn);
	return 0;
}

#else

SEC("kprobe/tcp_sendmsg")
int kprobe_http_tcp_sendmsg(struct pt_regs *ctx) { return 0; }

SEC("kprobe/tcp_recvmsg")
int kprobe_http_tcp_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kretprobe/tcp_recvmsg")
int kretprobe_http_tcp_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("uprobe/SSL_write")
int uprobe_SSL_write(struct pt_regs *ctx) { return 0; }

SEC("uprobe/SSL_read")
int uprobe_SSL_read(struct pt_regs *ctx) { return 0; }

SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx) { return 0; }

SEC("uprobe/gnutls_record_send")
int uprobe_gnutls_record_send(struct pt_regs *ctx) { return 0; }

SEC("uprobe/gnutls_record_recv")
int uprobe_gnutls_record_recv(struct pt_regs *ctx) { return 0; }

SEC("uretprobe/gnutls_record_recv")
int uretprobe_gnutls_record_recv(struct pt_regs *ctx) { return 0; }

#endif