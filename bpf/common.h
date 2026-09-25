// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_COMMON_H
#define PODTRACE_COMMON_H

#ifdef PODTRACE_VMLINUX_FROM_BTF
#include <vmlinux.h>
#else
#include "vmlinux.h"
#endif

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
#undef PT_REGS_PARM1
#undef PT_REGS_PARM2
#undef PT_REGS_PARM3
#undef PT_REGS_PARM4
#undef PT_REGS_PARM5
#undef PT_REGS_RC
#undef PT_REGS_IP
#undef PT_REGS_SP
#undef PT_REGS_FP

#if defined(__TARGET_ARCH_arm64)
struct pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_RC(x)    ((x)->regs[0])
#define PT_REGS_IP(x)    ((x)->pc)
#define PT_REGS_SP(x)    ((x)->sp)
#define PT_REGS_FP(x)    ((x)->regs[29])
#else
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
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RC(x)    ((x)->ax)
#define PT_REGS_IP(x)    ((x)->ip)
#define PT_REGS_SP(x)    ((x)->sp)
#define PT_REGS_FP(x)    ((x)->bp)
#endif

struct sockaddr_in {
	u16 sin_family;
	u16 sin_port;
	struct {
		u32 s_addr;
	} sin_addr;
	u8 sin_zero[8];
};

struct trace_entry {
	u16 type;
	u8  flags;
	u8  preempt_count;
	s32 pid;
};
struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long id;
	unsigned long args[6];
	char __data[0];
};

#ifndef __bpf_md_ptr
#define __bpf_md_ptr(type, name) \
	union {                      \
		type name;               \
		__u64 :64;               \
	} __attribute__((aligned(8)))
#endif

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
	__u8  tstamp_type;
	__u8  :8;
	__u16 :16;
	__u64 hwtstamp;
};

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;
	__u16 dst_port;
	__u16 :16;
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 is_fullsock;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__bpf_md_ptr(void *, skb_data);
	__bpf_md_ptr(void *, skb_data_end);
	__u32 skb_len;
	__u32 skb_tcp_flags;
	__u64 skb_hwtstamp;
};

_Static_assert(__builtin_offsetof(struct __sk_buff, sk) == 168, "__sk_buff.sk must match linux/bpf.h");
_Static_assert(sizeof(struct __sk_buff) == 192, "__sk_buff must match linux/bpf.h");
_Static_assert(__builtin_offsetof(struct bpf_sock_ops, srtt_us) == 80, "bpf_sock_ops.srtt_us must match linux/bpf.h");
_Static_assert(__builtin_offsetof(struct bpf_sock_ops, sk) == 184, "bpf_sock_ops.sk must match linux/bpf.h");
_Static_assert(sizeof(struct bpf_sock_ops) == 224, "bpf_sock_ops must match linux/bpf.h");
_Static_assert(sizeof(struct bpf_sock) == 80, "bpf_sock must match linux/bpf.h");

#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  4
#define BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB 5
#define BPF_SOCK_OPS_RTT_CB                 12
#define BPF_SOCK_OPS_RTT_CB_FLAG            (1 << 3)
#define BPF_SK_STORAGE_GET_F_CREATE         1
#define BPF_F_NO_PREALLOC                   (1U << 0)
#define BPF_MAP_TYPE_SK_STORAGE             24
#endif

#define MAX_STRING_LEN 128
#define MAX_STACK_DEPTH 64

#define NS_PER_MS 1000000ULL
#define PAGE_SIZE 4096
#define MAX_BYTES_THRESHOLD (10ULL * 1024ULL * 1024ULL)
#define MIN_LATENCY_NS (1ULL * NS_PER_MS)

#define AF_INET 2
#define AF_INET6 10
#define AF_ALG 38

struct podtrace_sockaddr_alg {
	u16 salg_family;
	u8  salg_type[14];
	u32 salg_feat;
	u32 salg_mask;
	u8  salg_name[64];
};
#define IPPROTO_TCP 6
#define EAGAIN 11
#define HEX_ADDR_LEN 16
#define COMM_LEN 16

#define PAGE_FAULT_SAMPLE_RATE 64

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif
#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif
#ifndef BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH 9
#endif
#ifndef BPF_MAP_TYPE_LRU_PERCPU_HASH
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif
#ifndef BPF_EXIST
#define BPF_EXIST 2
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK 256
#endif
_Static_assert(BPF_F_USER_STACK == (1U << 8), "BPF_F_USER_STACK must be 1<<8; 8 selects BPF_F_REUSE_STACKID and yields kernel frames");

#endif
