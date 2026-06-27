// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#ifdef PODTRACE_VMLINUX_FROM_BTF

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GO_ARG_PTR(ctx) ((void *)(ctx)->bx)
#define GO_ARG_LEN(ctx) ((u64)(ctx)->cx)
#define GO_TLS_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_ARG_PTR(ctx) ((void *)PT_REGS_PARM2(ctx))
#define GO_ARG_LEN(ctx) ((u64)PT_REGS_PARM3(ctx))
#define GO_TLS_SUPPORTED 1
#endif

#endif

#ifdef GO_TLS_SUPPORTED

#define GO_PEEK_LEN 16

SEC("uprobe/go_tls_write")
int uprobe_go_tls_write(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	void *base = GO_ARG_PTR(ctx);
	u64 avail = GO_ARG_LEN(ctx);
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