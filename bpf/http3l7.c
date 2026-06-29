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
#define GO_GOROUTINE(ctx) ((u64)(ctx)->r14)
#define GO_H3_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_REG0(ctx)      ((u64)PT_REGS_PARM1(ctx))
#define GO_REG1(ctx)      ((u64)PT_REGS_PARM2(ctx))
#define GO_REG2(ctx)      ((u64)PT_REGS_PARM3(ctx))
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

static __always_inline void h3_stash_request(u64 goroutine, u64 req)
{
	if (!req)
		return;
	struct h3_req_inflight in = {};
	in.start_ts = bpf_ktime_get_ns();
	in.method_len = (u8)read_go_str(req, GO_REQ_METHOD_OFF, in.method, H3_TXN_METHOD_MAX);

	u64 url = 0;
	if (bpf_probe_read_user(&url, sizeof(url), (void *)(req + GO_REQ_URL_OFF)) == 0 && url)
		in.path_len = (u16)read_go_str(url, GO_URL_PATH_OFF, in.path, H3_TXN_PATH_MAX);

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
		u64 sc = 0;
		if (bpf_probe_read_user(&sc, sizeof(sc), (void *)(resp + GO_RESP_STATUSCODE_OFF)) == 0)
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

#else

SEC("uprobe/h3_roundtrip")
int uprobe_h3_roundtrip(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_roundtrip_ret")
int uprobe_h3_roundtrip_ret(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_req_from_headers_ret")
int uprobe_h3_req_from_headers_ret(struct pt_regs *ctx) { return 0; }

SEC("uprobe/h3_write_header")
int uprobe_h3_write_header(struct pt_regs *ctx) { return 0; }

#endif
