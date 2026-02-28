// SPDX-License-Identifier: GPL-2.0
/*
 * gRPC tracing via HTTP/2 HEADERS frame inspection on tcp_sendmsg.
 *
 * Requires PODTRACE_VMLINUX_FROM_BTF for iov_iter field access.
 * Without BTF, this probe is a no-op.
 *
 * Mechanism:
 *   - A second kprobe on tcp_sendmsg (kprobe_grpc_tcp_sendmsg) filters
 *     traffic on the configured gRPC port (default 50051).
 *   - Reads the first 50 bytes of the TCP send buffer.
 *   - If the HTTP/2 frame type is HEADERS (0x1), scans the HPACK payload
 *     for a '/' byte — the gRPC method path always starts with '/'.
 *   - Stores the extracted path in grpc_methods[pid<<32|tid].
 *   - The existing kretprobe_tcp_sendmsg (network.c) is modified to check
 *     grpc_methods and emit EVENT_GRPC_METHOD when a method is found.
 *
 * HTTP/2 frame header (9 bytes):
 *   [0-2]  length (3 bytes, big-endian)
 *   [3]    type   (0=DATA, 1=HEADERS, 4=SETTINGS, ...)
 *   [4]    flags
 *   [5-8]  stream_id (4 bytes, MSB reserved)
 *   [9+]   payload (HPACK-encoded headers for HEADERS frame)
 *
 * HPACK shortcut used: for gRPC, :path is always a literal string
 * starting with '/'. We scan the payload bytes starting at offset 9
 * for the first '/' character.
 *
 * Field mapping:
 *   target  = "/Service/Method" path
 *   details = empty (status code populated at response — not traced here)
 *   bytes   = bytes sent (from tcp_sendmsg return value)
 *   latency_ns = sendmsg duration (from start_times set by kprobe_tcp_sendmsg)
 */

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#define GRPC_INSPECT_LEN 50   /* bytes to read from send buffer */
#define HTTP2_FRAME_HDR  9    /* HTTP/2 frame header size */

#ifdef PODTRACE_VMLINUX_FROM_BTF

/* kprobe_grpc_tcp_sendmsg — attached to tcp_sendmsg alongside the existing probe.
 *
 * This only populates grpc_methods[key]; it does NOT emit an event.
 * Event emission happens in kretprobe_tcp_sendmsg (network.c) which checks
 * grpc_methods after emitting EVENT_TCP_SEND.
 */
SEC("kprobe/tcp_sendmsg")
int kprobe_grpc_tcp_sendmsg(struct pt_regs *ctx)
{
	/* Filter by destination port — only inspect potential gRPC traffic */
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	/* skc_dport is in network byte order */
	u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (dport != GRPC_DEFAULT_PORT)
		return 0;

	/* Read first GRPC_INSPECT_LEN bytes from send buffer */
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	if (!msg)
		return 0;

	const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
	if (!iov)
		return 0;

	struct iovec iov_entry;
	if (bpf_probe_read_kernel(&iov_entry, sizeof(iov_entry), iov) != 0)
		return 0;

	if (!iov_entry.iov_base || iov_entry.iov_len < HTTP2_FRAME_HDR)
		return 0;

	u8 buf[GRPC_INSPECT_LEN] = {};
	u32 read_len = iov_entry.iov_len < GRPC_INSPECT_LEN ?
	               (u32)iov_entry.iov_len : GRPC_INSPECT_LEN;
	if (bpf_probe_read_user(buf, read_len & (GRPC_INSPECT_LEN - 1),
	                        iov_entry.iov_base) != 0)
		return 0;

	/* Check HTTP/2 frame type (byte 3 in the 9-byte frame header) */
	if (buf[3] != HTTP2_HEADERS)
		return 0;

	/* Scan payload (starts at byte 9) for first '/' — the gRPC path */
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	/* Check for the HTTP/2 client connection preface (initial SETTINGS frame).
	 * The preface starts with "PRI * HTTP/2.0" — skip it (not a gRPC call). */
	if (buf[0] == 'P' && buf[1] == 'R' && buf[2] == 'I')
		return 0;

	/* Scan for '/' in the HPACK payload */
	u32 path_start = 0;
	u32 i;
	for (i = HTTP2_FRAME_HDR; i < GRPC_INSPECT_LEN; i++) {
		if (buf[i] == '/') {
			path_start = i;
			break;
		}
	}

	if (path_start == 0)
		return 0;  /* No path found in this frame */

	/* Copy path from buf[path_start] until ':' (gRPC path ends before metadata) */
	char path[MAX_STRING_LEN] = {};
	u32 p = 0;
	for (i = path_start; i < GRPC_INSPECT_LEN && p < MAX_STRING_LEN - 1; i++) {
		u8 c = buf[i];
		/* Stop at non-printable or header separator characters */
		if (c < 0x20 || c == ':' || c == ' ')
			break;
		path[p++] = c;
	}
	if (p == 0)
		return 0;
	path[p] = '\0';

	bpf_map_update_elem(&grpc_methods, &key, path, BPF_ANY);
	return 0;
}

#else /* !PODTRACE_VMLINUX_FROM_BTF */

/* Non-BTF build: gRPC HTTP/2 inspection is disabled */
SEC("kprobe/tcp_sendmsg")
int kprobe_grpc_tcp_sendmsg(struct pt_regs *ctx) { return 0; }

#endif /* PODTRACE_VMLINUX_FROM_BTF */
