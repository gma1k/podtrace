// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF

#define QUICHE_HDR_STRIDE 32
#define QUICHE_HDR_MAX    32

struct quiche_h3_header_shadow {
	u64 name;
	u64 name_len;
	u64 value;
	u64 value_len;
};

struct quiche_iter_ctx {
	u64 headers;
	u32 count;
};

static long quiche_process_field(u64 name, u64 name_len, u64 value, u64 value_len)
{
	if (!name || !value || name_len == 0 || name_len > H3_HDR_NAME_MAX)
		return 0;

	u32 zero = 0;
	struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
	if (!s)
		return 1;
	struct h3_txn_record *rec = &s->rec;

	char nm[2 * H3_HDR_NAME_MAX] = {};
	u32 nlen = (u32)name_len;
	if (nlen == 0 || nlen > H3_HDR_NAME_MAX)
		return 0;
	asm volatile("" : "+r"(nlen));
	nlen &= (2 * H3_HDR_NAME_MAX) - 1;
	if (bpf_probe_read_user(nm, nlen, (void *)name) != 0)
		return 0;

	if (nlen == 7 && nm[0] == ':' && nm[1] == 'm' && nm[2] == 'e' &&
	    nm[3] == 't' && nm[4] == 'h' && nm[5] == 'o' && nm[6] == 'd') {
		u32 n = nghttp3_clamp_len(value_len, H3_TXN_METHOD_MAX);
		if (n && bpf_probe_read_user(rec->method, n, (void *)value) == 0)
			rec->method_len = (u8)n;
		return 0;
	}
	if (nlen == 5 && nm[0] == ':' && nm[1] == 'p' && nm[2] == 'a' &&
	    nm[3] == 't' && nm[4] == 'h') {
		u32 n = nghttp3_clamp_len(value_len, H3_TXN_PATH_MAX);
		if (n && bpf_probe_read_user(rec->path, n, (void *)value) == 0)
			rec->path_len = (u16)n;
		return 0;
	}
	if (nlen == 7 && nm[0] == ':' && nm[1] == 's' && nm[2] == 't' &&
	    nm[3] == 'a' && nm[4] == 't' && nm[5] == 'u' && nm[6] == 's') {
		rec->status = nghttp3_parse_status(value, value_len);
		return 0;
	}
	if (nlen == 11 && nm[0] == 't' && nm[1] == 'r' && nm[2] == 'a' &&
	    nm[3] == 'c' && nm[4] == 'e' && nm[5] == 'p' && nm[6] == 'a' &&
	    nm[7] == 'r' && nm[8] == 'e' && nm[9] == 'n' && nm[10] == 't') {
		u32 n = nghttp3_clamp_len(value_len, H3_TXN_TP_MAX);
		if (n && bpf_probe_read_user(rec->traceparent, n, (void *)value) == 0)
			rec->tp_len = (u8)n;
		return 0;
	}
	nghttp3_capture_hdr_rec(rec, nm, nlen, value, value_len);
	return 0;
}

static long quiche_hdr_cb(u32 idx, void *vctx)
{
	struct quiche_iter_ctx *c = vctx;
	if (idx >= c->count)
		return 1;
	struct quiche_h3_header_shadow h;
	void *addr = (void *)(c->headers + (u64)idx * QUICHE_HDR_STRIDE);
	if (bpf_probe_read_user(&h, sizeof(h), addr) != 0)
		return 1;
	return quiche_process_field(h.name, h.name_len, h.value, h.value_len);
}

static __always_inline struct h3_txn_record *quiche_collect(u64 headers, u64 headers_len)
{
	if (!headers || headers_len == 0)
		return NULL;
	u32 zero = 0;
	struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
	if (!s)
		return NULL;
	struct h3_txn_record *rec = &s->rec;
	__builtin_memset(rec, 0, sizeof(*rec));

	u32 count = headers_len > QUICHE_HDR_MAX ? QUICHE_HDR_MAX : (u32)headers_len;
	struct quiche_iter_ctx c = { .headers = headers, .count = count };
	bpf_loop(count, quiche_hdr_cb, &c, 0);

	if (rec->method_len == 0 && rec->path_len == 0 && rec->status == 0)
		return NULL;
	return rec;
}

SEC("uprobe/quiche_h3_send_request")
int uprobe_quiche_h3_send_request(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	struct h3_txn_record *rec =
		quiche_collect((u64)PT_REGS_PARM3(ctx), (u64)PT_REGS_PARM4(ctx));
	if (!rec)
		return 0;
	u64 tid = bpf_get_current_pid_tgid();
	struct h3_adapter_call call = { .conn = (u64)PT_REGS_PARM1(ctx) };
	bpf_map_update_elem(&h3_adapter_calls, &tid, &call, BPF_ANY);
	return 0;
}

SEC("uretprobe/quiche_h3_send_request")
int uretprobe_quiche_h3_send_request(struct pt_regs *ctx)
{
	u64 tid = bpf_get_current_pid_tgid();
	struct h3_adapter_call *call = bpf_map_lookup_elem(&h3_adapter_calls, &tid);
	if (!call)
		return 0;
	u64 conn = call->conn;
	bpf_map_delete_elem(&h3_adapter_calls, &tid);

	s64 stream_id = (s64)PT_REGS_RC(ctx);
	if (stream_id < 0)
		return 0;
	u32 zero = 0;
	struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
	if (!s || (s->rec.method_len == 0 && s->rec.path_len == 0))
		return 0;
	h3_adapter_stash_request(&s->rec, conn, (u64)stream_id);
	return 0;
}

SEC("uprobe/quiche_h3_send_response")
int uprobe_quiche_h3_send_response(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	struct h3_txn_record *rec =
		quiche_collect((u64)PT_REGS_PARM4(ctx), (u64)PT_REGS_PARM5(ctx));
	if (rec)
		h3_adapter_respond(rec, (u64)PT_REGS_PARM1(ctx),
				   (u64)PT_REGS_PARM3(ctx));
	return 0;
}

#define QUICHE_RS_HDR_STRIDE 48
#define QUICHE_RS_HDR_MAX    32

static long quiche_rs_hdr_cb(u32 idx, void *vctx)
{
	struct quiche_iter_ctx *c = vctx;
	if (idx >= c->count)
		return 1;
	u64 f[6];
	void *addr = (void *)(c->headers + (u64)idx * QUICHE_RS_HDR_STRIDE);
	if (bpf_probe_read_user(f, sizeof(f), addr) != 0)
		return 1;
	return quiche_process_field(f[1], f[2], f[4], f[5]);
}

SEC("uprobe/quiche_rs_send_request")
int uprobe_quiche_rs_send_request(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u64 headers = (u64)PT_REGS_PARM4(ctx);
	u64 count = (u64)PT_REGS_PARM5(ctx);
	if (!headers || count == 0)
		return 0;
	u32 zero = 0;
	struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
	if (!s)
		return 0;
	struct h3_txn_record *rec = &s->rec;
	__builtin_memset(rec, 0, sizeof(*rec));

	u32 n = count > QUICHE_RS_HDR_MAX ? QUICHE_RS_HDR_MAX : (u32)count;
	struct quiche_iter_ctx c = { .headers = headers, .count = n };
	bpf_loop(n, quiche_rs_hdr_cb, &c, 0);

	if (rec->method_len == 0 && rec->path_len == 0)
		return 0;
	rec->timestamp = bpf_ktime_get_ns();
	rec->adapter_conn = (u64)PT_REGS_PARM2(ctx);
	h3_adapter_emit(rec, 1, H3_TXN_F_REQ_ONLY);
	return 0;
}

SEC("uprobe/quiche_h3_conn_poll")
int uprobe_quiche_h3_conn_poll(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u64 tid = bpf_get_current_pid_tgid();
	struct h3_adapter_call call = { .conn = (u64)PT_REGS_PARM1(ctx) };
	bpf_map_update_elem(&h3_adapter_calls, &tid, &call, BPF_ANY);
	return 0;
}

SEC("uretprobe/quiche_h3_conn_poll")
int uretprobe_quiche_h3_conn_poll(struct pt_regs *ctx)
{
	u64 tid = bpf_get_current_pid_tgid();
	struct h3_adapter_call *call = bpf_map_lookup_elem(&h3_adapter_calls, &tid);
	if (!call)
		return 0;
	u64 conn = call->conn;
	bpf_map_delete_elem(&h3_adapter_calls, &tid);

	s64 stream_id = (s64)PT_REGS_RC(ctx);
	if (stream_id < 0)
		return 0;
	h3_adapter_first_inbound(conn, (u64)stream_id);
	return 0;
}

#else

SEC("uprobe/quiche_h3_send_request")
int uprobe_quiche_h3_send_request(struct pt_regs *ctx) { return 0; }

SEC("uretprobe/quiche_h3_send_request")
int uretprobe_quiche_h3_send_request(struct pt_regs *ctx) { return 0; }

SEC("uprobe/quiche_h3_send_response")
int uprobe_quiche_h3_send_response(struct pt_regs *ctx) { return 0; }

SEC("uprobe/quiche_rs_send_request")
int uprobe_quiche_rs_send_request(struct pt_regs *ctx) { return 0; }

SEC("uprobe/quiche_h3_conn_poll")
int uprobe_quiche_h3_conn_poll(struct pt_regs *ctx) { return 0; }

SEC("uretprobe/quiche_h3_conn_poll")
int uretprobe_quiche_h3_conn_poll(struct pt_regs *ctx) { return 0; }

#endif