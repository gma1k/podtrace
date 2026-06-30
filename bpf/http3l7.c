// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GO_REG0(ctx)      ((u64)(ctx)->ax)
#define GO_REG1(ctx)      ((u64)(ctx)->bx)
#define GO_REG2(ctx)      ((u64)(ctx)->cx)
#define GO_REG3(ctx)      ((u64)(ctx)->di)
#define GO_REG4(ctx)      ((u64)(ctx)->si)
#define GO_GOROUTINE(ctx) ((u64)(ctx)->r14)
#define GO_H3_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_REG0(ctx)      ((u64)PT_REGS_PARM1(ctx))
#define GO_REG1(ctx)      ((u64)PT_REGS_PARM2(ctx))
#define GO_REG2(ctx)      ((u64)PT_REGS_PARM3(ctx))
#define GO_REG3(ctx)      ((u64)PT_REGS_PARM4(ctx))
#define GO_REG4(ctx)      ((u64)PT_REGS_PARM5(ctx))
#define GO_GOROUTINE(ctx) ((u64)(ctx)->regs[28])
#define GO_H3_SUPPORTED 1
#endif

#endif

#ifdef GO_H3_SUPPORTED

#define GO_REQ_METHOD_OFF      0
#define GO_REQ_URL_OFF         16
#define GO_URL_PATH_OFF        56
#define GO_RESP_STATUSCODE_OFF 16

struct go_string {
	u64 ptr;
	u64 len;
};

static __always_inline u32 read_go_str(u64 base, u64 off, char *dst, u32 cap)
{
	struct go_string s = {};
	if (bpf_probe_read_user(&s, sizeof(s), (void *)(base + off)) != 0)
		return 0;
	if (s.ptr == 0 || s.len == 0)
		return 0;
	u32 n = s.len > cap ? cap : (u32)s.len;
	if (bpf_probe_read_user(dst, n, (void *)s.ptr) != 0)
		return 0;
	return n;
}

#define H3_MAX_FIELDS 64

struct go_header_field {
	struct go_string name;
	struct go_string value;
};

static __always_inline void h3_capture_tp(u64 goroutine, u64 name_ptr, u64 name_len,
					  u64 val_ptr, u64 val_len)
{
	if (name_len != 11 || !name_ptr || !val_ptr || val_len == 0)
		return;
	char nm[11];
	if (bpf_probe_read_user(nm, sizeof(nm), (void *)name_ptr) != 0)
		return;
	static const char want[11] = {'t', 'r', 'a', 'c', 'e', 'p', 'a', 'r', 'e', 'n', 't'};
#pragma unroll
	for (int i = 0; i < 11; i++) {
		if (nm[i] != want[i])
			return;
	}
	struct h3_pending_tp p = {};
	u32 n = val_len > H3_TXN_TP_MAX ? H3_TXN_TP_MAX : (u32)val_len;
	if (bpf_probe_read_user(p.buf, n, (void *)val_ptr) != 0)
		return;
	p.len = (u8)n;
	bpf_map_update_elem(&h3_pending_tp, &goroutine, &p, BPF_ANY);
}

static __always_inline struct h3_field_offsets h3_field_offs(void)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct h3_field_offsets *o = bpf_map_lookup_elem(&h3_offsets, &tgid);
	if (o)
		return *o;
	struct h3_field_offsets def = {
		.method = GO_REQ_METHOD_OFF,
		.url = GO_REQ_URL_OFF,
		.path = GO_URL_PATH_OFF,
		.status = GO_RESP_STATUSCODE_OFF,
	};
	return def;
}

static __always_inline void h3_stash_request(u64 goroutine, u64 req)
{
	if (!req)
		return;
	struct h3_field_offsets off = h3_field_offs();
	struct h3_req_inflight in = {};
	in.start_ts = bpf_ktime_get_ns();
	in.method_len = (u8)read_go_str(req, off.method, in.method, H3_TXN_METHOD_MAX);

	u64 url = 0;
	if (bpf_probe_read_user(&url, sizeof(url), (void *)(req + off.url)) == 0 && url)
		in.path_len = (u16)read_go_str(url, off.path, in.path, H3_TXN_PATH_MAX);

	bpf_map_update_elem(&h3_req_stash, &goroutine, &in, BPF_ANY);
}

static __always_inline void h3_emit_txn(u64 goroutine, u16 status, u8 is_client)
{
	struct h3_req_inflight *in = bpf_map_lookup_elem(&h3_req_stash, &goroutine);
	if (!in)
		return;

	u32 zero = 0;
	struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
	if (!s) {
		bpf_map_delete_elem(&h3_req_stash, &goroutine);
		return;
	}
	struct h3_txn_record *rec = &s->rec;
	u64 now = bpf_ktime_get_ns();

	rec->timestamp = in->start_ts;
	rec->latency_ns = now > in->start_ts ? now - in->start_ts : 0;
	rec->cgroup_id = bpf_get_current_cgroup_id();
	rec->pid = bpf_get_current_pid_tgid() >> 32;
	rec->status = status;
	rec->is_client = is_client;
	rec->method_len = in->method_len > H3_TXN_METHOD_MAX ? H3_TXN_METHOD_MAX : in->method_len;
	rec->path_len = in->path_len > H3_TXN_PATH_MAX ? H3_TXN_PATH_MAX : in->path_len;
	__builtin_memcpy(rec->method, in->method, H3_TXN_METHOD_MAX);
	__builtin_memcpy(rec->path, in->path, H3_TXN_PATH_MAX);

	rec->tp_len = 0;
	struct h3_pending_tp *tp = bpf_map_lookup_elem(&h3_pending_tp, &goroutine);
	if (tp) {
		rec->tp_len = tp->len > H3_TXN_TP_MAX ? H3_TXN_TP_MAX : tp->len;
		__builtin_memcpy(rec->traceparent, tp->buf, H3_TXN_TP_MAX);
		bpf_map_delete_elem(&h3_pending_tp, &goroutine);
	}

	bpf_map_delete_elem(&h3_req_stash, &goroutine);
	bpf_ringbuf_output(&h3_txn_events, rec, sizeof(*rec), 0);
}

SEC("uprobe/h3_roundtrip")
int uprobe_h3_roundtrip(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	h3_stash_request(GO_GOROUTINE(ctx), GO_REG1(ctx));
	return 0;
}

SEC("uprobe/h3_roundtrip_ret")
int uprobe_h3_roundtrip_ret(struct pt_regs *ctx)
{
	u64 resp = GO_REG0(ctx);
	u16 status = 0;
	if (resp) {
		struct h3_field_offsets off = h3_field_offs();
		u64 sc = 0;
		if (bpf_probe_read_user(&sc, sizeof(sc), (void *)(resp + off.status)) == 0)
			status = (u16)sc;
	}
	h3_emit_txn(GO_GOROUTINE(ctx), status, 1);
	return 0;
}

SEC("uprobe/h3_req_from_headers_ret")
int uprobe_h3_req_from_headers_ret(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	h3_stash_request(GO_GOROUTINE(ctx), GO_REG0(ctx));
	return 0;
}

SEC("uprobe/h3_write_header")
int uprobe_h3_write_header(struct pt_regs *ctx)
{
	h3_emit_txn(GO_GOROUTINE(ctx), (u16)GO_REG1(ctx), 0);
	return 0;
}

SEC("uprobe/h3_qpack_write_field")
int uprobe_h3_qpack_write_field(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	h3_capture_tp(GO_GOROUTINE(ctx), GO_REG1(ctx), GO_REG2(ctx),
		      GO_REG3(ctx), GO_REG4(ctx));
	return 0;
}

SEC("uprobe/h3_parse_headers")
int uprobe_h3_parse_headers(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	u64 g = GO_GOROUTINE(ctx);
	struct h3_parse_state st = { .fields_ptr = GO_REG3(ctx) };
	bpf_map_update_elem(&h3_parse_args, &g, &st, BPF_ANY);
	return 0;
}

struct h3_tp_iter_ctx {
	u64 data;
	u32 count;
	u64 goroutine;
};

static long h3_tp_field_cb(u32 idx, void *vctx)
{
	struct h3_tp_iter_ctx *c = vctx;
	if (idx >= c->count)
		return 1;
	struct go_header_field f;
	void *addr = (void *)(c->data + (u64)idx * sizeof(struct go_header_field));
	if (bpf_probe_read_user(&f, sizeof(f), addr) != 0)
		return 1;
	h3_capture_tp(c->goroutine, f.name.ptr, f.name.len, f.value.ptr, f.value.len);
	return 0;
}

SEC("uprobe/h3_parse_headers_ret")
int uprobe_h3_parse_headers_ret(struct pt_regs *ctx)
{
	u64 g = GO_GOROUTINE(ctx);
	struct h3_parse_state *st = bpf_map_lookup_elem(&h3_parse_args, &g);
	if (!st)
		return 0;
	u64 fields_ptr = st->fields_ptr;
	bpf_map_delete_elem(&h3_parse_args, &g);
	if (!fields_ptr)
		return 0;

	struct go_string slice; // {data ptr, len}; cap ignored
	if (bpf_probe_read_user(&slice, sizeof(slice), (void *)fields_ptr) != 0)
		return 0;
	if (!slice.ptr || slice.len == 0)
		return 0;

	u32 count = slice.len > H3_MAX_FIELDS ? H3_MAX_FIELDS : (u32)slice.len;
	struct h3_tp_iter_ctx c = {
		.data = slice.ptr,
		.count = count,
		.goroutine = g,
	};
	bpf_loop(count, h3_tp_field_cb, &c, 0);
	return 0;
}

#else

SEC("uprobe/h3_roundtrip")
int uprobe_h3_roundtrip(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_roundtrip_ret")
int uprobe_h3_roundtrip_ret(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_req_from_headers_ret")
int uprobe_h3_req_from_headers_ret(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_write_header")
int uprobe_h3_write_header(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_qpack_write_field")
int uprobe_h3_qpack_write_field(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_parse_headers")
int uprobe_h3_parse_headers(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_parse_headers_ret")
int uprobe_h3_parse_headers_ret(struct pt_regs *ctx) { return 0; }

#endif
