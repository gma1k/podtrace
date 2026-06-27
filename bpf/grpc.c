// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#define GRPC_INSPECT_LEN 50   /* bytes to read from send buffer */
#define HTTP2_FRAME_HDR  9    /* HTTP/2 frame header size */

#ifdef PODTRACE_VMLINUX_FROM_BTF

SEC("kprobe/tcp_sendmsg")
int kprobe_grpc_tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (dport != GRPC_DEFAULT_PORT)
		return 0;

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	if (!base || avail < HTTP2_FRAME_HDR)
		return 0;

	u8 buf[GRPC_INSPECT_LEN] = {};
	u32 read_len = (u32)avail;
	if (read_len > GRPC_INSPECT_LEN)
		read_len = GRPC_INSPECT_LEN;
	if (bpf_probe_read_user(buf, read_len, base) != 0)
		return 0;

	if (buf[3] != HTTP2_HEADERS)
		return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	u32 path_start = 0;
	u32 i;
	for (i = HTTP2_FRAME_HDR; i < GRPC_INSPECT_LEN; i++) {
		if (buf[i] == '/') {
			path_start = i;
			break;
		}
	}

	if (path_start == 0)
		return 0;

	char path[MAX_STRING_LEN] = {};
	u32 p = 0;
	for (i = path_start; i < GRPC_INSPECT_LEN && p < MAX_STRING_LEN - 1; i++) {
		u8 c = buf[i];
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

#else

SEC("kprobe/tcp_sendmsg")
int kprobe_grpc_tcp_sendmsg(struct pt_regs *ctx) { return 0; }

#endif
