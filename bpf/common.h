// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_COMMON_H
#define PODTRACE_COMMON_H

#include "vmlinux.h"

#ifndef __u8
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef short __s16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef PODTRACE_VMLINUX_FROM_BTF
/* Field names match kernel BTF (bpftool btf dump) and the __VMLINUX_H__ path
 * in bpf_tracing.h, which expects short register names without the 'r' prefix.
 * User-space ptrace.h uses rax/rdi/rsi, but kernel BTF uses ax/di/si. */
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
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
