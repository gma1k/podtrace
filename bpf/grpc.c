// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#define GRPC_INSPECT_LEN 128


SEC("kprobe/tcp_sendmsg")
int kprobe_grpc_tcp_sendmsg(struct pt_regs *ctx)
{
	if (!cgroup_allows(bpf_get_current_cgroup_id()))
		return 0;
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	u32 zero = 0;
	u32 *cfg = bpf_map_lookup_elem(&grpc_port_cfg, &zero);
	u16 want = (cfg && *cfg != 0 && *cfg <= 0xffff) ? (u16)*cfg : GRPC_DEFAULT_PORT;
	if (dport != want)
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

	if (buf[3] != HTTP2_HEADERS || !h2_frame_header_plausible(buf))
		return 0;

	u32 flen = ((u32)buf[0] << 16) | ((u32)buf[1] << 8) | (u32)buf[2];
	u8 flags = buf[4];
	u32 start = HTTP2_FRAME_HDR;
	u32 end = HTTP2_FRAME_HDR + flen;
	if (flags & HTTP2_FLAG_PADDED) {
		u32 pad = buf[HTTP2_FRAME_HDR];
		start += 1;
		if (start + pad > end)
			return 0;
		end -= pad;
	}
	if (flags & HTTP2_FLAG_PRIORITY)
		start += 5;
	if (end > read_len)
		end = read_len;

	u32 vstart = 0, vlen = 0;
	if (!hpack_literal_path(buf, GRPC_INSPECT_LEN - 1, start, end, &vstart, &vlen))
		return 0;
	if (buf[vstart & (GRPC_INSPECT_LEN - 1)] != '/')
		return 0;

	char path[MAX_STRING_LEN] = {};
	u32 p = 0;
	for (u32 i = 0; i < MAX_STRING_LEN - 1; i++) {
		if (i >= vlen)
			break;
		u8 c = buf[(vstart + i) & (GRPC_INSPECT_LEN - 1)];
		if (c < 0x21 || c > 0x7e)
			return 0;
		path[p++ & (MAX_STRING_LEN - 1)] = c;
	}
	if (p == 0)
		return 0;

	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	bpf_map_update_elem(&grpc_methods, &key, path, BPF_ANY);
	return 0;
}
