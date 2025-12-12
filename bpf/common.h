// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_COMMON_H
#define PODTRACE_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef PODTRACE_VMLINUX_FROM_BTF
struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

struct sockaddr_in {
	u16 sin_family;
	u16 sin_port;
	struct {
		u32 s_addr;
	} sin_addr;
	u8 sin_zero[8];
};
#endif

#define MAX_STRING_LEN 128
#define MAX_STACK_DEPTH 64

#define NS_PER_MS 1000000ULL
#define PAGE_SIZE 4096
#define MAX_BYTES_THRESHOLD (10ULL * 1024ULL * 1024ULL)
#define MIN_LATENCY_NS (1ULL * NS_PER_MS)

#define AF_INET 2
#define AF_INET6 10
#define EAGAIN 11
#define HEX_ADDR_LEN 16
#define COMM_LEN 16

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK 8
#endif

#endif
