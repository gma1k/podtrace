// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"
#include "hpack_huffman.h"

#define MAX_H2_FIELDS 16
#define H2_BUF_MASK   (H2_READ_LEN - 1)
#define H2_VAL_MASK   (H2_VAL_MAX - 1)

#ifdef PODTRACE_VMLINUX_FROM_BTF

static __always_inline struct h2_scratch *h2_scratch_lookup(void)
{
	u32 zero = 0;
	return bpf_map_lookup_elem(&h2_scratch_map, &zero);
}

static __always_inline u8 h2b(const u8 *buf, u32 i)
{
	return buf[i & H2_BUF_MASK];
}

static __always_inline void h2w(char *out, u32 i, char v)
{
	out[i & H2_VAL_MASK] = v;
}

static __always_inline char h2vr(const char *buf, u32 i)
{
	return buf[i & H2_VAL_MASK];
}

static __always_inline u32 hpack_int(const u8 *buf, u32 pos, u32 limit,
				     u32 prefix, u32 *out)
{
	u32 mask = (1u << prefix) - 1;
	u32 val = h2b(buf, pos) & mask;
	if (val < mask) {
		*out = val;
		return 1;
	}
	u32 consumed = 1, m = 0;
#pragma unroll
	for (u32 k = 0; k < 4; k++) {
		u32 p = pos + 1 + k;
		if (p >= limit)
			break;
		u8 c = h2b(buf, p);
		val += (u32)(c & 0x7f) << m;
		m += 7;
		consumed++;
		if (!(c & 0x80))
			break;
	}
	*out = val;
	return consumed;
}

struct h2_str {
	u32 start;
	u32 len;
	u32 next;
	u8 huff;
};

static __always_inline struct h2_str h2_str_hdr(const u8 *buf, u32 pos, u32 limit)
{
	struct h2_str r = {};
	r.huff = (h2b(buf, pos) & 0x80) ? 1 : 0;
	u32 len = 0;
	u32 consumed = hpack_int(buf, pos, limit, 7, &len);
	r.len = len;
	r.start = pos + consumed;
	r.next = r.start + len;
	return r;
}

static __always_inline int h2_name_class(u32 name_idx)
{
	if (name_idx == 2 || name_idx == 3)
		return 1;
	if (name_idx == 4 || name_idx == 5)
		return 2;
	if (name_idx >= 8 && name_idx <= 14)
		return 3;
	return 0;
}

static const u8 TP_NAME_HUFF[8] = { 0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f };

static __always_inline int h2_name_is_traceparent(const u8 *buf, struct h2_str ns)
{
	if (ns.huff) {
		if (ns.len != 8)
			return 0;
#pragma unroll
		for (u32 k = 0; k < 8; k++)
			if (h2b(buf, ns.start + k) != TP_NAME_HUFF[k])
				return 0;
		return 1;
	}
	if (ns.len != 11)
		return 0;
	static const char tp[11] = { 't', 'r', 'a', 'c', 'e', 'p', 'a', 'r', 'e', 'n', 't' };
#pragma unroll
	for (u32 k = 0; k < 11; k++)
		if (h2b(buf, ns.start + k) != (u8)tp[k])
			return 0;
	return 1;
}

static __always_inline char *h2_out_for_class(struct h2_scratch *s, int cls)
{
	if (cls == 1)
		return s->method;
	if (cls == 2)
		return s->path;
	if (cls == 3)
		return s->status;
	if (cls == 4)
		return s->tpval;
	return NULL;
}

struct h2_valctx {
	u32 in_start;
	u32 in_len;
	int cls;
	u8 huff;
};

static long hpack_val_cb(u32 i, void *vctx)
{
	struct h2_valctx *v = vctx;
	if (i >= v->in_len)
		return 1;
	struct h2_scratch *s = h2_scratch_lookup();
	if (!s)
		return 1;
	char *out = h2_out_for_class(s, v->cls);
	if (!out)
		return 1;

	u32 op = s->hop;
	u8 ib = h2b(s->buf, v->in_start + i);
	if (!v->huff) {
		if (op < H2_VAL_MAX - 1) {
			h2w(out, op, ib);
			s->hop = op + 1;
		}
		return 0;
	}

	u8 state = s->hstate;
	u8 nibs[2] = { (u8)(ib >> 4), (u8)(ib & 0xf) };
#pragma unroll
	for (u32 n = 0; n < 2; n++) {
		struct huff_entry e =
			huff_table[state & HUFF_STATE_MASK][nibs[n & 1] & 0xf];
		if (e.flags & (HUFF_FLAG_FAIL | HUFF_FLAG_EOS)) {
			s->hstate = state;
			s->hop = op;
			return 1;
		}
		if (e.flags & HUFF_FLAG_SYM) {
			if (op < H2_VAL_MAX - 1) {
				h2w(out, op, (char)e.sym);
				op++;
			}
		}
		state = e.next;
	}
	s->hstate = state;
	s->hop = op;
	return 0;
}

static __always_inline void h2_decode_loc(struct h2_scratch *s, int cls)
{
	struct h2_loc *loc = &s->wloc[cls & 7];
	if (!loc->present)
		return;
	struct h2_valctx v = {
		.in_start = loc->start,
		.in_len = loc->len,
		.huff = loc->huff,
		.cls = cls,
	};
	s->hop = 0;
	s->hstate = 0;
	u32 cap = loc->len > H2_VAL_MAX ? H2_VAL_MAX : loc->len;
	bpf_loop(cap, hpack_val_cb, &v, 0);
	char *out = h2_out_for_class(s, cls);
	if (out)
		h2w(out, s->hop, '\0');
}

static __always_inline void h2_set(char *out, const char *v, u32 n)
{
#pragma unroll
	for (u32 k = 0; k < 12; k++) {
		if (k >= n)
			break;
		h2w(out, k, v[k]);
	}
	h2w(out, n, '\0');
}

static __always_inline void h2_apply_indexed(struct h2_scratch *s,
					     u8 want_status, u32 idx)
{
	if (!want_status) {
		if (idx == 2)
			h2_set(s->method, "GET", 3);
		else if (idx == 3)
			h2_set(s->method, "POST", 4);
		else if (idx == 4)
			h2_set(s->path, "/", 1);
		else if (idx == 5)
			h2_set(s->path, "/index.html", 11);
		return;
	}
	switch (idx) {
	case 8:
		h2_set(s->status, "200", 3);
		break;
	case 9:
		h2_set(s->status, "204", 3);
		break;
	case 10:
		h2_set(s->status, "206", 3);
		break;
	case 11:
		h2_set(s->status, "304", 3);
		break;
	case 12:
		h2_set(s->status, "400", 3);
		break;
	case 13:
		h2_set(s->status, "404", 3);
		break;
	case 14:
		h2_set(s->status, "500", 3);
		break;
	}
}

struct h2_walk_ctx {
	u32 limit;
	u8 want_status;
};

static __always_inline void h2_record_loc(struct h2_scratch *s, int cls,
					  struct h2_str vs)
{
	struct h2_loc *loc = &s->wloc[cls & 7];
	if (loc->present)
		return;
	loc->start = vs.start;
	loc->len = vs.len;
	loc->huff = vs.huff;
	loc->present = 1;
}

static long h2_field_cb(u32 idx, void *vctx)
{
	struct h2_walk_ctx *c = vctx;
	struct h2_scratch *s = h2_scratch_lookup();
	if (!s)
		return 1;

	u32 pos = s->wpos;
	if (pos + 1 > c->limit || pos + 1 > H2_READ_LEN)
		return 1;

	u8 b = h2b(s->buf, pos);

	if (b & 0x80) {
		u32 val = 0;
		pos += hpack_int(s->buf, pos, c->limit, 7, &val);
		h2_apply_indexed(s, c->want_status, val);
		s->wpos = pos;
		return 0;
	}

	u32 prefix;
	if (b & 0x40) {
		prefix = 6;
	} else if (b & 0x20) {
		u32 val = 0;
		pos += hpack_int(s->buf, pos, c->limit, 5, &val);
		s->wpos = pos;
		return 0;
	} else {
		prefix = 4;
	}

	u32 name_idx = 0;
	pos += hpack_int(s->buf, pos, c->limit, prefix, &name_idx);

	int cls;
	if (name_idx == 0) {
		struct h2_str ns = h2_str_hdr(s->buf, pos, c->limit);
		pos = ns.next;
		cls = h2_name_is_traceparent(s->buf, ns) ? 4 : 0;
	} else {
		cls = h2_name_class(name_idx);
	}

	struct h2_str vs = h2_str_hdr(s->buf, pos, c->limit);
	if (c->want_status) {
		if (cls == 3)
			h2_record_loc(s, cls, vs);
	} else if (cls == 1 || cls == 2 || cls == 4) {
		h2_record_loc(s, cls, vs);
	}
	s->wpos = vs.next;
	return 0;
}

static __always_inline int h2_frame_at(const u8 *buf, u32 buflen, u32 o,
				       u32 *plen, u8 *type, u8 *flags)
{
	if (o + HTTP2_FRAME_HDR > buflen || o + 4 > H2_READ_LEN)
		return 0;
	*plen = ((u32)h2b(buf, o) << 16) | ((u32)h2b(buf, o + 1) << 8) |
		(u32)h2b(buf, o + 2);
	*type = h2b(buf, o + 3);
	*flags = h2b(buf, o + 4);
	return 1;
}

static __always_inline int h2_find_headers(const u8 *buf, u32 buflen,
					   u32 *poff, u32 *plen)
{
	u32 len = 0, hdr_off = 0, flags = 0;
	u8 ty = 0, fl = 0;

	if (h2_frame_at(buf, buflen, 0, &len, &ty, &fl) && ty == HTTP2_HEADERS) {
		hdr_off = HTTP2_FRAME_HDR;
		flags = fl;
	} else if (buflen >= 4 && buf[0] == 'P' && buf[1] == 'R' &&
		   buf[2] == 'I' && buf[3] == ' ' &&
		   h2_frame_at(buf, buflen, HTTP2_PREFACE_LEN, &len, &ty, &fl) &&
		   ty == HTTP2_HEADERS) {
		hdr_off = HTTP2_PREFACE_LEN + HTTP2_FRAME_HDR;
		flags = fl;
	} else {
		return 0;
	}

	if (flags & 0x08)
		hdr_off += 1;
	if (flags & 0x20)
		hdr_off += 5;

	*poff = hdr_off;
	*plen = len;
	return 1;
}

static __always_inline int h2_parse(struct h2_scratch *s, u32 rlen,
				    u8 want_status)
{
	u32 poff = 0, plen = 0;
	if (!h2_find_headers(s->buf, rlen, &poff, &plen))
		return 0;

	s->method[0] = '\0';
	s->path[0] = '\0';
	s->status[0] = '\0';
	s->tpval[0] = '\0';
	__builtin_memset(s->wloc, 0, sizeof(s->wloc));
	s->wpos = poff;

	u32 limit = poff + plen;
	if (limit > rlen)
		limit = rlen;
	if (limit > H2_READ_LEN)
		limit = H2_READ_LEN;

	struct h2_walk_ctx c = {
		.limit = limit,
		.want_status = want_status,
	};
	bpf_loop(MAX_H2_FIELDS, h2_field_cb, &c, 0);

	if (want_status) {
		h2_decode_loc(s, 3);
	} else {
		h2_decode_loc(s, 1);
		h2_decode_loc(s, 2);
		h2_decode_loc(s, 4);
	}
	return 1;
}

static __always_inline void h2_target_write(struct event *e, u32 i, char v)
{
	e->target[i & (MAX_STRING_LEN - 1)] = v;
}

static __always_inline void h2_emit_request_user(void *ctx, void *base,
						 u64 avail, u8 transport)
{
	if (!base || avail < HTTP2_FRAME_HDR)
		return;

	struct h2_scratch *s = h2_scratch_lookup();
	if (!s)
		return;

	u32 rlen = avail < H2_READ_LEN ? (u32)avail : H2_READ_LEN;
	if (bpf_probe_read_user(s->buf, rlen, base) != 0)
		return;

	if (!h2_parse(s, rlen, 0))
		return;
	if (h2vr(s->path, 0) != '/')
		return;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 now = bpf_ktime_get_ns();

	struct event *e = get_event_buf();
	if (!e)
		return;

	u32 ti = 0;
#pragma unroll
	for (u32 k = 0; k < 8; k++) {
		char mc = h2vr(s->method, k);
		if (!mc)
			break;
		h2_target_write(e, ti, mc);
		ti++;
	}
	if (ti == 0) {
		h2_target_write(e, 0, 'G');
		h2_target_write(e, 1, 'E');
		h2_target_write(e, 2, 'T');
		ti = 3;
	}
	h2_target_write(e, ti, ' ');
	ti++;
	for (u32 k = 0; k < H2_VAL_MAX; k++) {
		char pc = h2vr(s->path, k);
		if (!pc || ti >= MAX_STRING_LEN - 1)
			break;
		h2_target_write(e, ti, pc);
		ti++;
	}
	h2_target_write(e, ti, '\0');

	struct http_req req = {};
	req.start_ns = now;
	bpf_probe_read_kernel_str(req.endpoint, sizeof(req.endpoint), e->target);
	bpf_map_update_elem(&h2_reqs, &key, &req, BPF_ANY);

	e->timestamp = now;
	e->pid = pid;
	e->type = EVENT_HTTP_REQ;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = transport;

	if (h2vr(s->tpval, 0) != '\0') {
		static const char pfx[13] = { 't', 'r', 'a', 'c', 'e', 'p', 'a',
					      'r', 'e', 'n', 't', ':', ' ' };
		u32 di = 0;
#pragma unroll
		for (u32 k = 0; k < 13; k++) {
			e->details[di & (MAX_STRING_LEN - 1)] = pfx[k];
			di++;
		}
		for (u32 k = 0; k < H2_VAL_MAX; k++) {
			char tc = h2vr(s->tpval, k);
			if (!tc || di >= MAX_STRING_LEN - 1)
				break;
			e->details[di & (MAX_STRING_LEN - 1)] = tc;
			di++;
		}
		e->details[di & (MAX_STRING_LEN - 1)] = '\0';
	} else {
		e->details[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_h2_tcp_sendmsg(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	h2_emit_request_user(ctx, base, avail, HTTP_TRANSPORT_H2C);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_h2_tcp_recvmsg(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	if (!bpf_map_lookup_elem(&h2_reqs, &key))
		return 0;

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	if (!base)
		return 0;

	u64 base_val = (u64)base;
	bpf_map_update_elem(&h2_recv_base, &key, &base_val, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_h2_tcp_recvmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	u64 *base_ptr = bpf_map_lookup_elem(&h2_recv_base, &key);
	if (!base_ptr)
		return 0;
	void *base = (void *)*base_ptr;
	bpf_map_delete_elem(&h2_recv_base, &key);

	s64 ret = PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;

	struct http_req *req = bpf_map_lookup_elem(&h2_reqs, &key);
	if (!req)
		return 0;

	struct h2_scratch *s = h2_scratch_lookup();
	if (!s)
		return 0;

	u32 rlen = (u64)ret < H2_READ_LEN ? (u32)ret : H2_READ_LEN;
	if (bpf_probe_read_user(s->buf, rlen, base) != 0)
		return 0;

	if (!h2_parse(s, rlen, 1) || h2vr(s->status, 0) == '\0')
		return 0;

	u64 latency_ns = calc_latency(req->start_ns);
	s32 status_num = 0;
#pragma unroll
	for (u32 k = 0; k < 3; k++) {
		char d = h2vr(s->status, k);
		if (d < '0' || d > '9')
			break;
		status_num = status_num * 10 + (d - '0');
	}

	struct event *e = get_event_buf();
	if (e) {
		e->timestamp = bpf_ktime_get_ns();
		e->pid = pid;
		e->type = EVENT_HTTP_RESP;
		e->latency_ns = latency_ns;
		e->error = status_num >= 500 ? status_num : 0;
		e->bytes = (u64)ret;
		e->tcp_state = HTTP_TRANSPORT_H2C;
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), req->endpoint);
		bpf_probe_read_kernel_str(e->details, sizeof(e->details), s->status);
		capture_user_stack(ctx, pid, tid, e);
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	}
	bpf_map_delete_elem(&h2_reqs, &key);
	return 0;
}

#else

SEC("kprobe/tcp_sendmsg")
int kprobe_h2_tcp_sendmsg(struct pt_regs *ctx) { return 0; }

SEC("kprobe/tcp_recvmsg")
int kprobe_h2_tcp_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kretprobe/tcp_recvmsg")
int kretprobe_h2_tcp_recvmsg(struct pt_regs *ctx) { return 0; }

#endif