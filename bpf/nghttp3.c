// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF

#define NGHTTP3_NV_STRIDE 40
#define NGHTTP3_NV_MAX    32

struct nghttp3_nv_prefix {
	u64 name;
	u64 value;
	u64 namelen;
	u64 valuelen;
};

struct nghttp3_iter_ctx {
	u64 nva;
	u32 count;
};

static __always_inline u32 nghttp3_clamp_len(u64 v, u32 max)
{
	u32 n = (u32)v;
	asm volatile("" : "+r"(n));
	if (n > max)
		n = max;
	asm volatile("" : "+r"(n));
	return n;
}

static __always_inline u16 nghttp3_parse_status(u64 val_ptr, u64 val_len)
{
	if (val_len != 3)
		return 0;
	char d[3];
	if (bpf_probe_read_user(d, sizeof(d), (void *)val_ptr) != 0)
		return 0;
	if (d[0] < '0' || d[0] > '9' || d[1] < '0' || d[1] > '9' ||
	    d[2] < '0' || d[2] > '9')
		return 0;
	return (u16)((d[0] - '0') * 100 + (d[1] - '0') * 10 + (d[2] - '0'));
}

static __always_inline void nghttp3_capture_hdr_rec(struct h3_txn_record *rec,
						    const char *nm, u32 nlen,
						    u64 val_ptr, u64 val_len)
{
#pragma unroll
	for (int slot = 0; slot < H3_HDR_SLOTS; slot++) {
		u32 k = slot;
		struct h3_hdr_name *want = bpf_map_lookup_elem(&h3_hdr_names, &k);
		if (!want || want->len == 0 || want->len != nlen)
			continue;
		u32 diff = 0;
#pragma unroll
		for (int i = 0; i < H3_HDR_NAME_MAX; i++)
			diff |= (u32)((((u8)nm[i]) | 0x20) ^ (((u8)want->name[i]) | 0x20));
		if (diff)
			continue;
		u32 vn = nghttp3_clamp_len(val_len, H3_HDR_VAL_MAX);
		if (bpf_probe_read_user(rec->hdr_val[slot], vn, (void *)val_ptr) == 0)
			rec->hdr_vlen[slot] = (u8)vn;
		return;
	}
}

static long nghttp3_nv_cb(u32 idx, void *vctx)
{
	struct nghttp3_iter_ctx *c = vctx;
	if (idx >= c->count)
		return 1;
	struct nghttp3_nv_prefix nv;
	void *addr = (void *)(c->nva + (u64)idx * NGHTTP3_NV_STRIDE);
	if (bpf_probe_read_user(&nv, sizeof(nv), addr) != 0)
		return 1;
	if (!nv.name || !nv.value || nv.namelen == 0 ||
	    nv.namelen > H3_HDR_NAME_MAX)
		return 0;

	u32 zero = 0;
	struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
	if (!s)
		return 1;
	struct h3_txn_record *rec = &s->rec;

	char nm[2 * H3_HDR_NAME_MAX] = {};
	u32 nlen = (u32)nv.namelen;
	if (nlen == 0 || nlen > H3_HDR_NAME_MAX)
		return 0;
	asm volatile("" : "+r"(nlen));
	nlen &= (2 * H3_HDR_NAME_MAX) - 1;
	if (bpf_probe_read_user(nm, nlen, (void *)nv.name) != 0)
		return 0;

	if (nlen == 7 && nm[0] == ':' && nm[1] == 'm' && nm[2] == 'e' &&
	    nm[3] == 't' && nm[4] == 'h' && nm[5] == 'o' && nm[6] == 'd') {
		u32 n = nghttp3_clamp_len(nv.valuelen, H3_TXN_METHOD_MAX);
		if (n && bpf_probe_read_user(rec->method, n, (void *)nv.value) == 0)
			rec->method_len = (u8)n;
		return 0;
	}
	if (nlen == 5 && nm[0] == ':' && nm[1] == 'p' && nm[2] == 'a' &&
	    nm[3] == 't' && nm[4] == 'h') {
		u32 n = nghttp3_clamp_len(nv.valuelen, H3_TXN_PATH_MAX);
		if (n && bpf_probe_read_user(rec->path, n, (void *)nv.value) == 0)
			rec->path_len = (u16)n;
		return 0;
	}
	if (nlen == 7 && nm[0] == ':' && nm[1] == 's' && nm[2] == 't' &&
	    nm[3] == 'a' && nm[4] == 't' && nm[5] == 'u' && nm[6] == 's') {
		rec->status = nghttp3_parse_status(nv.value, nv.valuelen);
		return 0;
	}
	if (nlen == 11 && nm[0] == 't' && nm[1] == 'r' && nm[2] == 'a' &&
	    nm[3] == 'c' && nm[4] == 'e' && nm[5] == 'p' && nm[6] == 'a' &&
	    nm[7] == 'r' && nm[8] == 'e' && nm[9] == 'n' && nm[10] == 't') {
		u32 n = nghttp3_clamp_len(nv.valuelen, H3_TXN_TP_MAX);
		if (n && bpf_probe_read_user(rec->traceparent, n, (void *)nv.value) == 0)
			rec->tp_len = (u8)n;
		return 0;
	}
	nghttp3_capture_hdr_rec(rec, nm, nlen, nv.value, nv.valuelen);
	return 0;
}

static __always_inline struct h3_txn_record *nghttp3_collect(u64 nva, u64 nvlen)
{
	if (!nva || nvlen == 0)
		return NULL;
	u32 zero = 0;
	struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
	if (!s)
		return NULL;
	struct h3_txn_record *rec = &s->rec;
	__builtin_memset(rec, 0, sizeof(*rec));

	u32 count = nvlen > NGHTTP3_NV_MAX ? NGHTTP3_NV_MAX : (u32)nvlen;
	struct nghttp3_iter_ctx c = { .nva = nva, .count = count };
	bpf_loop(count, nghttp3_nv_cb, &c, 0);

	if (rec->method_len == 0 && rec->path_len == 0 && rec->status == 0)
		return NULL;
	return rec;
}

static __always_inline struct h3_adapter_stream_key
h3_adapter_key(u64 conn, u64 stream_id)
{
	struct h3_adapter_stream_key k = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
		.conn = conn,
		.stream_id = stream_id,
	};
	return k;
}

static __always_inline void h3_adapter_emit(struct h3_txn_record *rec,
					    u8 is_client, u8 flags)
{
	rec->cgroup_id = bpf_get_current_cgroup_id();
	rec->pid = bpf_get_current_pid_tgid() >> 32;
	rec->is_client = is_client;
	rec->flags = flags;
	bpf_ringbuf_output(&h3_txn_events, rec, sizeof(*rec), 0);
}

static __always_inline void h3_adapter_first_inbound(u64 conn, u64 stream_id)
{
	struct h3_adapter_stream_key k = h3_adapter_key(conn, stream_id);
	struct h3_txn_record *st = bpf_map_lookup_elem(&h3_adapter_streams, &k);
	if (!st) {
		u32 zero = 0;
		struct h3_txn_scratch *s = bpf_map_lookup_elem(&h3_txn_scratch_map, &zero);
		if (!s)
			return;
		struct h3_txn_record *rec = &s->rec;
		__builtin_memset(rec, 0, sizeof(*rec));
		rec->timestamp = bpf_ktime_get_ns();
		rec->flags = H3_ADAPTER_KIND_ARRIVAL;
		bpf_map_update_elem(&h3_adapter_streams, &k, rec, BPF_ANY);
		return;
	}
	if (st->flags != H3_ADAPTER_KIND_REQUEST)
		return;
	u64 now = bpf_ktime_get_ns();
	st->latency_ns = now > st->timestamp ? now - st->timestamp : 0;
	st->status = 0;
	h3_adapter_emit(st, 1, 0);
	bpf_map_delete_elem(&h3_adapter_streams, &k);
}

static __always_inline void h3_adapter_stash_request(struct h3_txn_record *rec,
						     u64 conn, u64 stream_id)
{
	struct h3_adapter_stream_key k = h3_adapter_key(conn, stream_id);
	rec->timestamp = bpf_ktime_get_ns();
	rec->flags = H3_ADAPTER_KIND_REQUEST;
	bpf_map_update_elem(&h3_adapter_streams, &k, rec, BPF_ANY);
}

static __always_inline void h3_adapter_respond(struct h3_txn_record *rec,
					       u64 conn, u64 stream_id)
{
	u64 now = bpf_ktime_get_ns();
	rec->timestamp = now;
	struct h3_adapter_stream_key k = h3_adapter_key(conn, stream_id);
	struct h3_txn_record *st = bpf_map_lookup_elem(&h3_adapter_streams, &k);
	if (st && st->flags == H3_ADAPTER_KIND_ARRIVAL) {
		rec->timestamp = st->timestamp;
		rec->latency_ns = now > st->timestamp ? now - st->timestamp : 0;
		bpf_map_delete_elem(&h3_adapter_streams, &k);
	}
	h3_adapter_emit(rec, 0, H3_TXN_F_RESP_ONLY);
}

SEC("uprobe/nghttp3_submit_request")
int uprobe_nghttp3_submit_request(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	struct h3_txn_record *rec =
		nghttp3_collect((u64)PT_REGS_PARM3(ctx), (u64)PT_REGS_PARM4(ctx));
	if (rec)
		h3_adapter_stash_request(rec, (u64)PT_REGS_PARM1(ctx),
					 (u64)PT_REGS_PARM2(ctx));
	return 0;
}

SEC("uprobe/nghttp3_submit_response")
int uprobe_nghttp3_submit_response(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	struct h3_txn_record *rec =
		nghttp3_collect((u64)PT_REGS_PARM3(ctx), (u64)PT_REGS_PARM4(ctx));
	if (rec)
		h3_adapter_respond(rec, (u64)PT_REGS_PARM1(ctx),
				   (u64)PT_REGS_PARM2(ctx));
	return 0;
}

SEC("uprobe/nghttp3_read_stream")
int uprobe_nghttp3_read_stream(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	h3_adapter_first_inbound((u64)PT_REGS_PARM1(ctx), (u64)PT_REGS_PARM2(ctx));
	return 0;
}

#else

SEC("uprobe/nghttp3_submit_request")
int uprobe_nghttp3_submit_request(struct pt_regs *ctx) { return 0; }

SEC("uprobe/nghttp3_submit_response")
int uprobe_nghttp3_submit_response(struct pt_regs *ctx) { return 0; }

SEC("uprobe/nghttp3_read_stream")
int uprobe_nghttp3_read_stream(struct pt_regs *ctx) { return 0; }

#endif