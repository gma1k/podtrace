// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#if defined(PODTRACE_VMLINUX_FROM_BTF) && \
	(defined(__TARGET_ARCH_x86) || defined(__x86_64__))

#define GO_PEEK_LEN 16

SEC("uprobe/go_tls_write")
int uprobe_go_tls_write(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	void *base = (void *)ctx->bx;
	u64 avail = (u64)ctx->cx;
	if (!base || avail < HTTP2_FRAME_HDR)
		return 0;

	u8 peek[GO_PEEK_LEN] = {};
	u32 plen = avail < GO_PEEK_LEN ? (u32)avail : GO_PEEK_LEN;
	if (bpf_probe_read_user(peek, plen, base) != 0)
		return 0;

	if (http_method_len(peek) > 0)
		http_emit_request(ctx, base, avail, HTTP_TRANSPORT_TLS);
	else
		h2_emit_request_user(ctx, base, avail, HTTP_TRANSPORT_H2_TLS);
	return 0;
}

#else

SEC("uprobe/go_tls_write")
int uprobe_go_tls_write(struct pt_regs *ctx) { return 0; }

#endif
