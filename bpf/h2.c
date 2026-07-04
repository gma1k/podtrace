// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF

static __always_inline struct h2_hdr_scratch *h2_hdr_scratch_lookup(void)
{
	u32 zero = 0;
	return bpf_map_lookup_elem(&h2_hdr_scratch_map, &zero);
}

static __always_inline u32 h2_next_seq(u64 conn_id, u32 dir)
{
	struct h2_seq_key k = { .conn_id = conn_id, .dir = dir, ._pad = 0 };
	u64 *cur = bpf_map_lookup_elem(&h2_seq, &k);
	if (cur) {
		u32 seq = (u32)*cur;
		*cur = *cur + 1;
		return seq;
	}
	u64 one = 1;
	bpf_map_update_elem(&h2_seq, &k, &one, BPF_ANY);
	return 0;
}

struct h2_raw_ctx {
	void *base;
	u64 conn_id;
	u64 cgroup_id;
	u64 ts;
	u32 avail;
	u32 pid;
	u32 dir;
	u8  transport;
};

static __always_inline int h2_preface_signal(void *base, u64 avail)
{
	u8 b[16];
	if (avail >= 16) {
		if (bpf_probe_read_user(b, 16, base) != 0)
			return 0;
		if (b[0] == 'P' && b[1] == 'R' && b[2] == 'I' && b[3] == ' ' &&
		    b[4] == '*' && b[5] == ' ' && b[6] == 'H' && b[7] == 'T' &&
		    b[8] == 'T' && b[9] == 'P' && b[10] == '/' && b[11] == '2' &&
		    b[12] == '.' && b[13] == '0' && b[14] == '\r' && b[15] == '\n')
			return 2;
		return 0;
	}
	if (avail >= 4) {
		if (bpf_probe_read_user(b, 4, base) != 0)
			return 0;
		if (b[0] == 'P' && b[1] == 'R' && b[2] == 'I' && b[3] == ' ')
			return 1;
	}
	return 0;
}

static __always_inline int h2_start_looks_h2(void *base, u64 avail)
{
	if (avail < HTTP2_FRAME_HDR)
		return 0;
	u8 fh[HTTP2_FRAME_HDR];
	if (bpf_probe_read_user(fh, sizeof(fh), base) != 0)
		return 0;
	if (fh[0] == 'P' && fh[1] == 'R' && fh[2] == 'I' && fh[3] == ' ')
		return 1;
	if (fh[0] >= 0x14 && fh[0] <= 0x17 && fh[1] == 0x03 && fh[2] <= 0x04)
		return 0;
	return fh[3] <= HTTP2_CONTINUATION;
}

static long h2_frames_cb(u32 idx, void *vctx)
{
	struct h2_raw_ctx *c = vctx;
	struct h2_hdr_scratch *s = h2_hdr_scratch_lookup();
	if (!s)
		return 1;
	struct h2_seq_key fk = { .conn_id = c->conn_id, .dir = c->dir };
	struct h2_frame_state *fs = bpf_map_lookup_elem(&h2_frame_state, &fk);
	if (!fs)
		return 1;

	u32 off = s->off;
	if (off >= c->avail)
		return 1;

	if (fs->remaining > 0) {
		u32 avail_here = c->avail - off;
		u32 take = avail_here < fs->remaining ? avail_here : fs->remaining;
		u8 type = fs->type;
		if (type == HTTP2_HEADERS || type == HTTP2_CONTINUATION) {
			u32 frag = take > H2_HDR_FRAG_MAX ? H2_HDR_FRAG_MAX : take;
			if (frag > 0 &&
			    bpf_probe_read_user(s->frag, frag, (u8 *)c->base + off) == 0) {
				u8 completes = (fs->remaining - frag) == 0;
				s->rec.conn_id = c->conn_id;
				s->rec.timestamp = c->ts;
				s->rec.cgroup_id = c->cgroup_id;
				s->rec.pid = c->pid;
				s->rec.seq = h2_next_seq(c->conn_id, c->dir);
				s->rec.stream_id = fs->stream_id;
				s->rec.frag_len = (u16)frag;
				s->rec.direction = (u8)c->dir;
				s->rec.transport = c->transport;
				s->rec.flags =
					((completes && (fs->flags & HTTP2_FLAG_END_HEADERS)) ? H2_HDR_FLAG_END_HEADERS : 0) |
					((type == HTTP2_CONTINUATION) ? H2_HDR_FLAG_CONTINUATION : 0);
				fill_h2_record_peer(&s->rec, c->dir);
				bpf_ringbuf_output(&h2_hdr_events, &s->rec,
						   sizeof(s->rec) + frag, 0);
			}
			off += frag;
			fs->remaining -= frag;
		} else {
			off += take;
			fs->remaining -= take;
		}
		s->off = off;
		return 0;
	}

	if (off + HTTP2_FRAME_HDR > c->avail)
		return 1;
	u8 fh[HTTP2_FRAME_HDR];
	if (bpf_probe_read_user(fh, sizeof(fh), (u8 *)c->base + off) != 0)
		return 1;
	u32 flen = ((u32)fh[0] << 16) | ((u32)fh[1] << 8) | (u32)fh[2];
	u8 type = fh[3];
	u8 flags = fh[4];
	u32 sid = (((u32)fh[5] << 24) | ((u32)fh[6] << 16) |
		   ((u32)fh[7] << 8) | (u32)fh[8]) & 0x7fffffff;
	off += HTTP2_FRAME_HDR;

	if (type == HTTP2_HEADERS) {
		if ((flags & HTTP2_FLAG_PADDED) && off < c->avail) {
			u8 pb = 0;
			if (bpf_probe_read_user(&pb, 1, (u8 *)c->base + off) == 0) {
				off += 1;
				flen = flen >= 1 ? flen - 1 : 0;
				flen = flen >= pb ? flen - pb : 0;
			}
		}
		if (flags & HTTP2_FLAG_PRIORITY) {
			off += 5;
			flen = flen >= 5 ? flen - 5 : 0;
		}
	}
	fs->type = type;
	fs->flags = flags;
	fs->stream_id = sid;
	fs->remaining = flen;
	s->off = off;
	return 0;
}

#define H2_MAX_FRAME_STEPS 48

static __always_inline void h2_emit_frames(void *base, u64 avail, u64 conn,
					   u32 dir, u8 transport)
{
	if (!base || avail == 0)
		return;

	u8 *known = bpf_map_lookup_elem(&h2_conns, &conn);
	if (!known) {
		if (!h2_start_looks_h2(base, avail))
			return;
		u8 one = 1;
		bpf_map_update_elem(&h2_conns, &conn, &one, BPF_ANY);
	}

	struct h2_seq_key fk = { .conn_id = conn, .dir = dir };
	struct h2_frame_state *fs = bpf_map_lookup_elem(&h2_frame_state, &fk);
	if (!fs) {
		struct h2_frame_state init = {};
		bpf_map_update_elem(&h2_frame_state, &fk, &init, BPF_ANY);
		fs = bpf_map_lookup_elem(&h2_frame_state, &fk);
		if (!fs)
			return;
	}

	struct h2_hdr_scratch *s = h2_hdr_scratch_lookup();
	if (!s)
		return;

	u32 start = 0;
	int pfx = h2_preface_signal(base, avail);
	if (pfx == 2 || (pfx == 1 && fs->remaining == 0)) {
		struct h2_seq_key ke = { .conn_id = conn, .dir = H2_DIR_EGRESS };
		struct h2_seq_key ki = { .conn_id = conn, .dir = H2_DIR_INGRESS };
		bpf_map_delete_elem(&h2_seq, &ke);
		bpf_map_delete_elem(&h2_seq, &ki);
		bpf_map_delete_elem(&h2_frame_state, &ke);
		bpf_map_delete_elem(&h2_frame_state, &ki);

		__builtin_memset(&s->rec, 0, sizeof(s->rec));
		s->rec.conn_id = conn;
		s->rec.timestamp = bpf_ktime_get_ns();
		s->rec.flags = H2_HDR_FLAG_CLOSE;
		bpf_ringbuf_output(&h2_hdr_events, &s->rec, sizeof(s->rec), 0);

		struct h2_frame_state fresh = {};
		bpf_map_update_elem(&h2_frame_state, &fk, &fresh, BPF_ANY);
		fs = bpf_map_lookup_elem(&h2_frame_state, &fk);
		if (!fs)
			return;

		if (avail < HTTP2_PREFACE_LEN) {
			fs->preface_seen = 1;
			fs->type = HTTP2_SETTINGS;
			fs->remaining = HTTP2_PREFACE_LEN - (u32)avail;
			return;
		}
		start = HTTP2_PREFACE_LEN;
	}
	fs->preface_seen = 1;
	s->off = start;

	struct h2_raw_ctx c = {
		.base = base,
		.conn_id = conn,
		.cgroup_id = bpf_get_current_cgroup_id(),
		.ts = bpf_ktime_get_ns(),
		.avail = avail < 0xffffffffULL ? (u32)avail : 0xffffffffU,
		.pid = bpf_get_current_pid_tgid() >> 32,
		.dir = dir,
		.transport = transport,
	};
	bpf_loop(H2_MAX_FRAME_STEPS, h2_frames_cb, &c, 0);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_h2_tcp_sendmsg(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	u64 conn = (u64)PT_REGS_PARM1(ctx);
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	h2_emit_frames(base, avail, conn, H2_DIR_EGRESS, HTTP_TRANSPORT_H2C);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_h2_tcp_recvmsg(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	if (!base)
		return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	struct h2_recv_info info = {
		.base = (u64)base,
		.conn_id = (u64)PT_REGS_PARM1(ctx),
	};
	bpf_map_update_elem(&h2_recv_base, &key, &info, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_h2_tcp_recvmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	struct h2_recv_info *info = bpf_map_lookup_elem(&h2_recv_base, &key);
	if (!info)
		return 0;
	void *base = (void *)info->base;
	u64 conn = info->conn_id;
	bpf_map_delete_elem(&h2_recv_base, &key);

	s64 ret = PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;

	h2_emit_frames(base, (u64)ret, conn, H2_DIR_INGRESS, HTTP_TRANSPORT_H2C);
	return 0;
}

SEC("kprobe/tcp_close")
int kprobe_h2_tcp_close(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	u64 conn = (u64)PT_REGS_PARM1(ctx);

	struct h2_seq_key ke = { .conn_id = conn, .dir = H2_DIR_EGRESS };
	struct h2_seq_key ki = { .conn_id = conn, .dir = H2_DIR_INGRESS };
	bpf_map_delete_elem(&h2_seq, &ke);
	bpf_map_delete_elem(&h2_seq, &ki);
	bpf_map_delete_elem(&h2_frame_state, &ke);
	bpf_map_delete_elem(&h2_frame_state, &ki);
	bpf_map_delete_elem(&h2_conns, &conn);

	struct h2_hdr_scratch *s = h2_hdr_scratch_lookup();
	if (!s)
		return 0;
	__builtin_memset(&s->rec, 0, sizeof(s->rec));
	s->rec.conn_id = conn;
	s->rec.timestamp = bpf_ktime_get_ns();
	s->rec.flags = H2_HDR_FLAG_CLOSE;
	bpf_ringbuf_output(&h2_hdr_events, &s->rec, sizeof(s->rec), 0);
	return 0;
}

#else

SEC("kprobe/tcp_sendmsg")
int kprobe_h2_tcp_sendmsg(struct pt_regs *ctx) { return 0; }

SEC("kprobe/tcp_recvmsg")
int kprobe_h2_tcp_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kretprobe/tcp_recvmsg")
int kretprobe_h2_tcp_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kprobe/tcp_close")
int kprobe_h2_tcp_close(struct pt_regs *ctx) { return 0; }

#endif