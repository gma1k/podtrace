// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

SEC("tp/exceptions/page_fault_user")
int tracepoint_page_fault_user(void *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	u32 zero = 0;
	u64 *seq = bpf_map_lookup_elem(&page_fault_seq, &zero);
	if (!seq) {
		return 0;
	}
	*seq += 1;
	if (*seq % PAGE_FAULT_SAMPLE_RATE != 0) {
		return 0;
	}

	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_PAGE_FAULT;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, e->pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

struct oom_mark_victim_hdr {
	unsigned char common[8];
	int pid;
};
_Static_assert(__builtin_offsetof(struct oom_mark_victim_hdr, pid) == 8, "mark_victim: pid must be at offset 8");

SEC("tp/oom/mark_victim")
int tracepoint_oom_mark_victim(void *ctx) {
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->type = EVENT_OOM_KILL;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';

#ifdef PODTRACE_VMLINUX_FROM_BTF
	struct trace_event_raw_mark_victim *tp = ctx;
	e->pid = BPF_CORE_READ(tp, pid);
	if (bpf_core_field_exists(tp->__data_loc_comm)) {
		u32 comm_loc = BPF_CORE_READ(tp, __data_loc_comm);
		unsigned short comm_off = (unsigned short)(comm_loc & 0xffff);
		unsigned short comm_len = (unsigned short)(comm_loc >> 16);
		if (comm_off >= sizeof(struct oom_mark_victim_hdr) && comm_off < 4096 &&
		    comm_len > 0 && comm_len <= COMM_LEN + 1) {
			bpf_probe_read_kernel_str(e->target, COMM_LEN, (char *)ctx + comm_off);
			__builtin_memcpy(e->comm, e->target, COMM_LEN);
		}
	}
#else
	struct oom_mark_victim_hdr hdr = {};
	if (bpf_probe_read_kernel(&hdr, sizeof(hdr), ctx) == 0) {
		e->pid = hdr.pid;
	}
#endif

	capture_user_stack(ctx, e->pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}
