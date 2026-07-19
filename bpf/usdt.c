// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

static __always_inline u32 usdt_put_char(char *buf, u32 pos, char c)
{
	pos &= (MAX_STRING_LEN - 1);
	buf[pos] = c;
	return pos + 1;
}

static __always_inline u32 usdt_put_hex(char *buf, u32 pos, u64 val, int nbytes)
{
	pos = usdt_put_char(buf, pos, '0');
	pos = usdt_put_char(buf, pos, 'x');
#pragma unroll
	for (int i = 15; i >= 0; i--) {
		if (i >= nbytes * 2)
			continue;
		u8 nib = (val >> (i * 4)) & 0xf;
		char c = nib < 10 ? '0' + nib : 'a' + (nib - 10);
		pos = usdt_put_char(buf, pos, c);
	}
	return pos;
}

static __always_inline u64 usdt_read_arg(struct pt_regs *ctx, struct usdt_arg *a)
{
	if (a->kind == USDT_ARG_CONST)
		return (u64)a->disp;
	if (a->kind != USDT_ARG_REG && a->kind != USDT_ARG_MEM)
		return 0;

	u32 off = a->reg_off;
	if (off > sizeof(struct pt_regs) - sizeof(u64))
		return 0;
	u64 reg = 0;
	bpf_probe_read_kernel(&reg, sizeof(reg), (u8 *)ctx + off);
	if (a->kind == USDT_ARG_REG)
		return reg;

	u64 mem = 0;
	bpf_probe_read_user(&mem, sizeof(mem), (void *)(reg + (u64)a->disp));
	return mem;
}

static __always_inline u64 usdt_mask_to_width(u64 val, int nbytes)
{
	if (nbytes >= 8)
		return val;
	u64 mask = ((u64)1 << (nbytes * 8)) - 1;
	return val & mask;
}

SEC("uprobe/usdt")
int uprobe_usdt(struct pt_regs *ctx)
{
	u64 cookie = bpf_get_attach_cookie(ctx);
	struct usdt_probe *p = bpf_map_lookup_elem(&usdt_probes, &cookie);
	if (!p)
		return 0;

	struct event *e = get_event_buf();
	if (!e)
		return 0;

	e->timestamp = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->type = EVENT_USDT;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;

	bpf_probe_read_kernel_str(e->target, sizeof(e->target), p->provider);

	int nl = bpf_probe_read_kernel_str(e->details, sizeof(e->details), p->name);
	u32 pos = nl > 0 ? (u32)(nl - 1) : 0;

	u8 nargs = p->nargs;
	if (nargs > USDT_MAX_ARGS)
		nargs = USDT_MAX_ARGS;
#pragma unroll
	for (int i = 0; i < USDT_MAX_ARGS; i++) {
		if (i >= nargs)
			continue;
		struct usdt_arg *a = &p->args[i];
		pos = usdt_put_char(e->details, pos, ' ');
		pos = usdt_put_char(e->details, pos, 'a');
		pos = usdt_put_char(e->details, pos, '0' + i);
		pos = usdt_put_char(e->details, pos, '=');
		if (a->kind == USDT_ARG_UNSUPPORTED) {
			pos = usdt_put_char(e->details, pos, '?');
			continue;
		}
		int w = a->size < 0 ? -a->size : a->size;
		if (w > 8)
			w = 8;
		if (w < 1)
			w = 1;
		u64 val = usdt_mask_to_width(usdt_read_arg(ctx, a), w);
		pos = usdt_put_hex(e->details, pos, val, w);
	}
	pos &= (MAX_STRING_LEN - 1);
	e->details[pos] = 0;

	u32 pid = e->pid;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}
