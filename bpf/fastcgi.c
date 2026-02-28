// SPDX-License-Identifier: GPL-2.0
/*
 * FastCGI / PHP-FPM tracing via unix domain socket kprobes.
 *
 * Requires PODTRACE_VMLINUX_FROM_BTF for iov_iter access.
 * Without BTF, all probes are no-ops (return 0 immediately).
 *
 * FastCGI protocol overview (per spec):
 *   Record header (8 bytes):
 *     [0] version   (always 1)
 *     [1] type      (1=BEGIN_REQUEST, 3=END_REQUEST, 4=PARAMS, 5=STDIN, 6=STDOUT)
 *     [2-3] requestId (big-endian u16)
 *     [4-5] contentLength (big-endian u16)
 *     [6]   paddingLength
 *     [7]   reserved
 *
 * From the php-fpm worker's perspective:
 *   - kretprobe/unix_stream_recvmsg: php-fpm receives PARAMS from nginx → extract URI/method
 *   - kprobe/unix_stream_sendmsg: php-fpm sends END_REQUEST back → emit response event
 *
 * Field mapping:
 *   EVENT_FASTCGI_REQUEST: target=REQUEST_URI, details=REQUEST_METHOD
 *   EVENT_FASTCGI_RESPONSE: target=REQUEST_URI, error=appStatus, latency_ns=request latency
 */

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF

/* Read the first `buf_size` bytes from the first iovec of a msghdr.
 * Returns 0 on success, negative on failure. */
static __always_inline int read_msghdr_data(struct msghdr *msg, void *buf, u32 buf_size)
{
	if (!msg || !buf || buf_size == 0)
		return -1;

	const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
	if (!iov)
		return -1;

	struct iovec iov_entry;
	if (bpf_probe_read_kernel(&iov_entry, sizeof(iov_entry), iov) != 0)
		return -1;

	if (!iov_entry.iov_base || iov_entry.iov_len < buf_size)
		return -1;

	return bpf_probe_read_user(buf, buf_size, iov_entry.iov_base);
}

/* -----------------------------------------------------------------------
 * kprobe/unix_stream_recvmsg — save msghdr* for kretprobe use
 * -----------------------------------------------------------------------
 * Called when a unix socket read is initiated.
 * Signature: int unix_stream_recvmsg(struct socket *sock, struct msghdr *msg,
 *                                     size_t size, int flags)
 * PARM2 = struct msghdr *
 */
SEC("kprobe/unix_stream_recvmsg")
int kprobe_unix_stream_recvmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	u64 msg_ptr = (u64)PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&recvmsg_args, &key, &msg_ptr, BPF_ANY);
	return 0;
}

/* -----------------------------------------------------------------------
 * kretprobe/unix_stream_recvmsg — parse FastCGI PARAMS record
 * -----------------------------------------------------------------------
 * After the recvmsg returns, the buffer has been filled.
 * Look for FCGI_PARAMS (type=4) and extract REQUEST_URI / REQUEST_METHOD.
 */
SEC("kretprobe/unix_stream_recvmsg")
int kretprobe_unix_stream_recvmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	u64 *msg_ptr_stored = bpf_map_lookup_elem(&recvmsg_args, &key);
	if (!msg_ptr_stored) return 0;
	u64 msg_ptr = *msg_ptr_stored;
	bpf_map_delete_elem(&recvmsg_args, &key);

	if (PT_REGS_RC(ctx) <= 0) return 0;

	struct msghdr *msg = (struct msghdr *)msg_ptr;
	u8 hdr[FCGI_HEADER_LEN];
	if (read_msghdr_data(msg, hdr, FCGI_HEADER_LEN) != 0)
		return 0;

	/* Validate FastCGI version and record type */
	if (hdr[0] != FCGI_VERSION_1)
		return 0;
	if (hdr[1] != FCGI_PARAMS)
		return 0;

	u16 request_id = ((u16)hdr[2] << 8) | hdr[3];
	u16 content_len = ((u16)hdr[4] << 8) | hdr[5];
	if (content_len == 0)
		return 0;

	/* FastCGI request key: lower 32 bits = requestId */
	u64 req_key = get_key(pid, tid) ^ (u64)request_id;

	struct event *e = get_event_buf();
	if (!e) return 0;

	/* Read PARAMS body — scan for REQUEST_URI */
	u8 params[FCGI_PARAMS_SCAN_LEN] = {};
	u32 scan_len = content_len < FCGI_PARAMS_SCAN_LEN ? content_len : FCGI_PARAMS_SCAN_LEN;

	const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
	if (!iov) return 0;

	struct iovec iov_entry;
	if (bpf_probe_read_kernel(&iov_entry, sizeof(iov_entry), iov) != 0)
		return 0;

	/* Params start after the 8-byte header */
	u8 *params_base = (u8 *)iov_entry.iov_base + FCGI_HEADER_LEN;
	if (bpf_probe_read_user(params, scan_len & 0xFF, params_base) != 0)
		return 0;

	/* Linear scan: find "REQUEST_URI" (11 bytes) in the params buffer.
	 * In FastCGI NV format, name comes first. After "REQUEST_URI" we skip
	 * the NV length bytes and find the value (the URI starts with '/'). */
	u8 found_uri = 0, found_method = 0;
	u32 i;

	for (i = 0; i + 14 < FCGI_PARAMS_SCAN_LEN - 3; i++) {
		if (found_uri && found_method)
			break;

		/* REQUEST_URI (11 bytes) */
		if (!found_uri && params[i] == 'R' && i + 11 < FCGI_PARAMS_SCAN_LEN) {
			if (params[i+1] == 'E' && params[i+2] == 'Q' && params[i+3] == 'U' &&
			    params[i+4] == 'E' && params[i+5] == 'S' && params[i+6] == 'T' &&
			    params[i+7] == '_' && params[i+8] == 'U' && params[i+9] == 'R' &&
			    params[i+10] == 'I') {
				/* Scan forward for the '/' that starts the URI value */
				u32 j;
				for (j = i + 11; j + 1 < FCGI_PARAMS_SCAN_LEN; j++) {
					if (params[j] == '/') {
						/* Copy URI into event buffer.
						 * Max is min(remaining bytes, MAX_STRING_LEN-1). */
						u32 copy = FCGI_PARAMS_SCAN_LEN - j;
						if (copy >= MAX_STRING_LEN)
							copy = MAX_STRING_LEN - 1;
						bpf_probe_read_kernel(e->target, copy & (MAX_STRING_LEN - 1),
						                     &params[j]);
						e->target[MAX_STRING_LEN - 1] = '\0';
						found_uri = 1;
						break;
					}
				}
			}
		}

		/* REQUEST_METHOD (14 bytes) */
		if (!found_method && params[i] == 'R' && i + 14 < FCGI_PARAMS_SCAN_LEN) {
			if (params[i+1] == 'E' && params[i+2] == 'Q' && params[i+3] == 'U' &&
			    params[i+4] == 'E' && params[i+5] == 'S' && params[i+6] == 'T' &&
			    params[i+7] == '_' && params[i+8] == 'M' && params[i+9] == 'E' &&
			    params[i+10] == 'T' && params[i+11] == 'H' && params[i+12] == 'O' &&
			    params[i+13] == 'D') {
				/* Value follows: typical methods are GET/POST/PUT 3-6 chars */
				u32 j;
				for (j = i + 14; j < FCGI_PARAMS_SCAN_LEN && j < i + 20; j++) {
					/* Skip non-alpha (NV length bytes) to find the method text */
					if ((params[j] >= 'A' && params[j] <= 'Z') ||
					    (params[j] >= 'a' && params[j] <= 'z')) {
						u32 copy = 15;
						if (j + copy > FCGI_PARAMS_SCAN_LEN)
							copy = FCGI_PARAMS_SCAN_LEN - j;
						bpf_probe_read_kernel(e->details, copy & 0xF,
						                     &params[j]);
						e->details[15] = '\0';
						found_method = 1;
						break;
					}
				}
			}
		}
	}

	if (!found_uri && !found_method)
		return 0;  /* Not a PARAMS record we can decode */

	if (!found_uri) e->target[0] = '\0';
	if (!found_method) e->details[0] = '\0';

	/* Store request state for END_REQUEST correlation */
	struct fastcgi_req req = {};
	req.start_ns = bpf_ktime_get_ns();
	bpf_probe_read_kernel_str(req.uri, sizeof(req.uri), e->target);
	bpf_probe_read_kernel_str(req.method, sizeof(req.method), e->details);
	bpf_map_update_elem(&fastcgi_reqs, &req_key, &req, BPF_ANY);

	/* Emit EVENT_FASTCGI_REQUEST */
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

/* -----------------------------------------------------------------------
 * kprobe/unix_stream_sendmsg — detect FastCGI END_REQUEST (php-fpm → nginx)
 * -----------------------------------------------------------------------
 * Signature: int unix_stream_sendmsg(struct socket *sock, struct msghdr *msg,
 *                                     size_t total_len)
 * PARM2 = struct msghdr *msg
 */
SEC("kprobe/unix_stream_sendmsg")
int kprobe_unix_stream_sendmsg(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u8 hdr[FCGI_HEADER_LEN + 8] = {};  /* header + END_REQUEST body */
	if (read_msghdr_data(msg, hdr, sizeof(hdr)) != 0)
		return 0;

	/* Must be FastCGI version 1 and END_REQUEST (type 3) */
	if (hdr[0] != FCGI_VERSION_1|| hdr[1] != FCGI_END_REQUEST)
		return 0;

	u16 request_id = ((u16)hdr[2] << 8) | hdr[3];
	u64 req_key = get_key(pid, tid) ^ (u64)request_id;

	struct fastcgi_req *req = bpf_map_lookup_elem(&fastcgi_reqs, &req_key);
	if (!req) return 0;

	/* END_REQUEST body (8 bytes): [0-3]=appStatus (big-endian), [4]=protocolStatus */
	u32 app_status = ((u32)hdr[8] << 24) | ((u32)hdr[9] << 16) |
	                 ((u32)hdr[10] << 8) | hdr[11];

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

#else /* !PODTRACE_VMLINUX_FROM_BTF */

/* Non-BTF build: FastCGI probes are no-ops */
SEC("kprobe/unix_stream_recvmsg")
int kprobe_unix_stream_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kretprobe/unix_stream_recvmsg")
int kretprobe_unix_stream_recvmsg(struct pt_regs *ctx) { return 0; }

SEC("kprobe/unix_stream_sendmsg")
int kprobe_unix_stream_sendmsg(struct pt_regs *ctx) { return 0; }

#endif /* PODTRACE_VMLINUX_FROM_BTF */
