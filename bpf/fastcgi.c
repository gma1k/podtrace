// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF

SEC("kprobe/unix_stream_recvmsg")
int kprobe_unix_stream_recvmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 user_ptr = 0;
	if (msg) {
		u8 it = BPF_CORE_READ(msg, msg_iter.iter_type);
		if (it == ITER_UBUF) {
			user_ptr = (u64)BPF_CORE_READ(msg, msg_iter.ubuf);
		} else if (it == ITER_IOVEC) {
			const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
			if (iov) {
				struct iovec iov_entry;
				if (bpf_probe_read_kernel(&iov_entry, sizeof(iov_entry), iov) == 0)
					user_ptr = (u64)iov_entry.iov_base;
			}
		}
	}
	if (user_ptr)
		bpf_map_update_elem(&recvmsg_args, &key, &user_ptr, BPF_ANY);
	return 0;
}

SEC("kretprobe/unix_stream_recvmsg")
int kretprobe_unix_stream_recvmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	u64 *user_ptr_stored = bpf_map_lookup_elem(&recvmsg_args, &key);
	if (!user_ptr_stored) return 0;
	u64 user_ptr = *user_ptr_stored;
	bpf_map_delete_elem(&recvmsg_args, &key);

	long rc_bytes = (long)PT_REGS_RC(ctx);
	if (rc_bytes <= 0 || !user_ptr) return 0;

	u16 request_id;
	u16 content_len;
	u32 params_buf_offset;

	struct fcgi_pending *pending = bpf_map_lookup_elem(&fastcgi_pending, &key);
	if (pending) {
		struct fcgi_pending p = *pending;
		bpf_map_delete_elem(&fastcgi_pending, &key);
		if (p.expected_body_bytes != 0 && (u32)rc_bytes == p.expected_body_bytes) {
			request_id = (u16)p.request_id;
			content_len = p.expected_body_bytes > FCGI_PARAMS_SCAN_LEN
				? FCGI_PARAMS_SCAN_LEN
				: (u16)p.expected_body_bytes;
			params_buf_offset = 0;
			goto emit_params;
		}
	}

	u8 hdr[24] = {};
	u32 read_size = rc_bytes >= 24 ? 24 : (rc_bytes >= FCGI_HEADER_LEN ? FCGI_HEADER_LEN : 0);
	if (read_size == 0)
		return 0;
	if (bpf_probe_read_user(hdr, read_size, (void *)user_ptr) != 0)
		return 0;

	if (hdr[0] != FCGI_VERSION_1)
		return 0;

	if (hdr[1] == FCGI_PARAMS) {
		request_id  = ((u16)hdr[2] << 8) | hdr[3];
		content_len = ((u16)hdr[4] << 8) | hdr[5];
		params_buf_offset = FCGI_HEADER_LEN;

		if ((u32)rc_bytes == FCGI_HEADER_LEN && content_len > 0) {
			u8 padding_len = hdr[6];
			struct fcgi_pending p = {
				.request_id = request_id,
				.expected_body_bytes = (u32)content_len + (u32)padding_len,
			};
			bpf_map_update_elem(&fastcgi_pending, &key, &p, BPF_ANY);
			return 0;
		}
	} else if (hdr[1] == FCGI_BEGIN_REQUEST && read_size >= 24 &&
	           hdr[16] == FCGI_VERSION_1 && hdr[17] == FCGI_PARAMS) {
		request_id  = ((u16)hdr[18] << 8) | hdr[19];
		content_len = ((u16)hdr[20] << 8) | hdr[21];
		params_buf_offset = 16 + FCGI_HEADER_LEN;
	} else {
		return 0;
	}
	if (content_len == 0)
		return 0;

emit_params: ;

	u64 req_key = get_key(pid, tid) ^ (u64)request_id;

	struct event *e = get_event_buf();
	if (!e) return 0;

	u8 params[FCGI_PARAMS_SCAN_LEN] = {};
	u32 scan_len = content_len < FCGI_PARAMS_SCAN_LEN ? content_len : FCGI_PARAMS_SCAN_LEN;

	u32 avail = (u32)rc_bytes > params_buf_offset ? (u32)rc_bytes - params_buf_offset : 0;
	if (scan_len > avail)
		scan_len = avail;
	if (scan_len == 0)
		return 0;

	u8 *params_base = (u8 *)user_ptr + params_buf_offset;
	if (bpf_probe_read_user(params, scan_len & 0xFF, params_base) != 0)
		return 0;

	u8 found_uri = 0, found_method = 0;
	u32 i;

	for (i = 0; i + 14 < FCGI_PARAMS_SCAN_LEN - 3; i++) {
		if (found_uri && found_method)
			break;

		if (!found_uri && params[i] == 'R' && i + 11 < FCGI_PARAMS_SCAN_LEN) {
			if (params[i+1] == 'E' && params[i+2] == 'Q' && params[i+3] == 'U' &&
			    params[i+4] == 'E' && params[i+5] == 'S' && params[i+6] == 'T' &&
			    params[i+7] == '_' && params[i+8] == 'U' && params[i+9] == 'R' &&
			    params[i+10] == 'I') {
				u32 vstart = (i + 11) & (FCGI_PARAMS_SCAN_LEN - 1);
				if (params[vstart] == '/') {
					u32 copy = FCGI_PARAMS_SCAN_LEN - vstart;
					if (i >= 2) {
						u8 vlen = params[(i - 1) & (FCGI_PARAMS_SCAN_LEN - 1)];
						if ((vlen & FCGI_NV_LEN_4BYTE) == 0 && vlen > 0 && vlen < copy)
							copy = vlen;
					}
					if (copy >= MAX_STRING_LEN)
						copy = MAX_STRING_LEN - 1;
					if (vstart + copy > FCGI_PARAMS_SCAN_LEN)
						copy = FCGI_PARAMS_SCAN_LEN - vstart;
					bpf_probe_read_kernel(e->target, copy & (MAX_STRING_LEN - 1),
					                     &params[vstart]);
					e->target[copy & (MAX_STRING_LEN - 1)] = '\0';
					found_uri = 1;
				}
			}
		}

		if (!found_method && params[i] == 'R' && i + 14 < FCGI_PARAMS_SCAN_LEN) {
			if (params[i+1] == 'E' && params[i+2] == 'Q' && params[i+3] == 'U' &&
			    params[i+4] == 'E' && params[i+5] == 'S' && params[i+6] == 'T' &&
			    params[i+7] == '_' && params[i+8] == 'M' && params[i+9] == 'E' &&
			    params[i+10] == 'T' && params[i+11] == 'H' && params[i+12] == 'O' &&
			    params[i+13] == 'D') {
				u32 vstart = (i + 14) & (FCGI_PARAMS_SCAN_LEN - 1);
				u8 c0 = params[vstart];
				if ((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z')) {
					u32 copy = 15;
					if (i >= 2) {
						u8 vlen = params[(i - 1) & (FCGI_PARAMS_SCAN_LEN - 1)];
						if ((vlen & FCGI_NV_LEN_4BYTE) == 0 && vlen > 0 && vlen < copy)
							copy = vlen;
					}
					if (vstart + copy > FCGI_PARAMS_SCAN_LEN)
						copy = FCGI_PARAMS_SCAN_LEN - vstart;
					bpf_probe_read_kernel(e->details, copy & 0xF,
					                     &params[vstart]);
					e->details[copy & 0xF] = '\0';
					found_method = 1;
				}
			}
		}
	}

	if (!found_uri && !found_method)
		return 0;

	if (!found_uri) e->target[0] = '\0';
	if (!found_method) e->details[0] = '\0';

	struct fastcgi_req req = {};
	req.start_ns = bpf_ktime_get_ns();
	bpf_probe_read_kernel_str(req.uri, sizeof(req.uri), e->target);
	bpf_probe_read_kernel_str(req.method, sizeof(req.method), e->details);
	bpf_map_update_elem(&fastcgi_reqs, &req_key, &req, BPF_ANY);

	e->timestamp  = req.start_ns;
	e->pid        = pid;
	e->type       = EVENT_FASTCGI_REQUEST;
	e->latency_ns = 0;
	e->error      = 0;
	e->bytes      = 0;
	e->tcp_state  = 0;
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}


SEC("kprobe/unix_stream_sendmsg")
int kprobe_unix_stream_sendmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	if (!msg) return 0;

	void *user_base = msghdr_user_base(msg, NULL);
	if (!user_base) return 0;

	const u32 FCGI_MAX_RECORD_BODY = 8 * 1024;
	u32 offset = 0;
	u8 hdr[16] = {};
	u8 found_end = 0;
	u16 request_id = 0;
	u32 app_status = 0;

	#pragma unroll
	for (int k = 0; k < 4; k++) {
		if (bpf_probe_read_user(hdr, sizeof(hdr), (u8 *)user_base + offset) != 0)
			break;
		if (hdr[0] != FCGI_VERSION_1)
			break;
		u16 content_len = ((u16)hdr[4] << 8) | hdr[5];
		u8 padding_len = hdr[6];
		if (hdr[1] == FCGI_END_REQUEST) {
			request_id = ((u16)hdr[2] << 8) | hdr[3];
			app_status = ((u32)hdr[8] << 24) | ((u32)hdr[9] << 16) |
			             ((u32)hdr[10] << 8) | hdr[11];
			found_end = 1;
			break;
		}
		if (content_len > FCGI_MAX_RECORD_BODY)
			break;
		offset += FCGI_HEADER_LEN + (u32)content_len + (u32)padding_len;
	}
	if (!found_end)
		return 0;

	u64 req_key = get_key(pid, tid) ^ (u64)request_id;

	struct fastcgi_req *req = bpf_map_lookup_elem(&fastcgi_reqs, &req_key);
	if (!req) return 0;

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&fastcgi_reqs, &req_key);
		return 0;
	}

	e->timestamp  = bpf_ktime_get_ns();
	e->pid        = pid;
	e->type       = EVENT_FASTCGI_RESPONSE;
	e->latency_ns = e->timestamp > req->start_ns ? e->timestamp - req->start_ns : 0;
	e->error      = (s32)app_status;
	e->bytes      = 0;
	e->tcp_state  = 0;
	bpf_probe_read_kernel_str(e->target, sizeof(e->target), req->uri);
	bpf_probe_read_kernel_str(e->details, sizeof(e->details), req->method);

	bpf_map_delete_elem(&fastcgi_reqs, &req_key);

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

#else

SEC("kprobe/unix_stream_recvmsg")
int kprobe_unix_stream_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kretprobe/unix_stream_recvmsg")
int kretprobe_unix_stream_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kprobe/unix_stream_sendmsg")
int kprobe_unix_stream_sendmsg(struct pt_regs *ctx) { return 0; }

#endif
