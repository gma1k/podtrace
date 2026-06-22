// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

SEC("tp/syscalls/sys_enter_bind")
int tracepoint_sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
	void *uaddr = (void *)(ctx->args[1]);
	if (!uaddr) {
		return 0;
	}

	struct podtrace_sockaddr_alg sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) != 0) {
		return 0;
	}
	if (sa.salg_family != AF_ALG) {
		return 0;
	}

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->type = EVENT_AF_ALG;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = bpf_get_current_uid_gid() & 0xffffffff;
	e->tcp_state = 0;
	bpf_probe_read_kernel_str(e->target, sizeof(sa.salg_type), sa.salg_type);
	bpf_probe_read_kernel_str(e->details, sizeof(sa.salg_name), sa.salg_name);

	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}