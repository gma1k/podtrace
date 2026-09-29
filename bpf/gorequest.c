// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "helpers.h"
#include "oncpu.h"

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GO_REQUEST_GOROUTINE(ctx) ((u64)(ctx)->r14)
#define GO_REQUEST_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_REQUEST_GOROUTINE(ctx) ((u64)(ctx)->regs[28])
#define GO_REQUEST_SUPPORTED 1
#endif

#ifdef GO_REQUEST_SUPPORTED

static __always_inline int go_request_begin(struct pt_regs *ctx, u32 kind)
{
	oncpu_begin_goroutine(GO_REQUEST_GOROUTINE(ctx), kind, bpf_ktime_get_ns());
	return 0;
}

static __always_inline int go_request_end(struct pt_regs *ctx, u32 kind)
{
	oncpu_finish_goroutine(GO_REQUEST_GOROUTINE(ctx), kind);
	return 0;
}

SEC("uprobe/go_nethttp_serve")
int uprobe_go_nethttp_serve(struct pt_regs *ctx) { return go_request_begin(ctx, ONCPU_GO_NETHTTP); }

SEC("uprobe/go_nethttp_serve_ret")
int uprobe_go_nethttp_serve_ret(struct pt_regs *ctx) { return go_request_end(ctx, ONCPU_GO_NETHTTP); }

SEC("uprobe/go_h2_handler")
int uprobe_go_h2_handler(struct pt_regs *ctx) { return go_request_begin(ctx, ONCPU_GO_H2); }

SEC("uprobe/go_h2_handler_ret")
int uprobe_go_h2_handler_ret(struct pt_regs *ctx) { return go_request_end(ctx, ONCPU_GO_H2); }

SEC("uprobe/go_h2_serve_conn")
int uprobe_go_h2_serve_conn(struct pt_regs *ctx)
{
	oncpu_abandon_goroutine(GO_REQUEST_GOROUTINE(ctx), ONCPU_GO_NETHTTP);
	return 0;
}

SEC("uprobe/go_grpc_handle_stream")
int uprobe_go_grpc_handle_stream(struct pt_regs *ctx) { return go_request_begin(ctx, ONCPU_GO_GRPC); }

SEC("uprobe/go_grpc_handle_stream_ret")
int uprobe_go_grpc_handle_stream_ret(struct pt_regs *ctx) { return go_request_end(ctx, ONCPU_GO_GRPC); }

#else

SEC("uprobe/go_nethttp_serve")
int uprobe_go_nethttp_serve(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_nethttp_serve_ret")
int uprobe_go_nethttp_serve_ret(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_h2_handler")
int uprobe_go_h2_handler(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_h2_handler_ret")
int uprobe_go_h2_handler_ret(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_h2_serve_conn")
int uprobe_go_h2_serve_conn(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_grpc_handle_stream")
int uprobe_go_grpc_handle_stream(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_grpc_handle_stream_ret")
int uprobe_go_grpc_handle_stream_ret(struct pt_regs *ctx) { return 0; }

#endif
