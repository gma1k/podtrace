// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include <bpf/bpf_endian.h>

static __always_inline void rtt_fill_target(struct bpf_sock_ops *skops, struct event *e)
{
	u16 port = (u16)bpf_ntohl(skops->remote_port);

	if (skops->family == AF_INET6) {
		u32 words[4];
		words[0] = skops->remote_ip6[0];
		words[1] = skops->remote_ip6[1];
		words[2] = skops->remote_ip6[2];
		words[3] = skops->remote_ip6[3];

		u8 addr6[16];
		__builtin_memcpy(addr6, words, sizeof(addr6));
		format_ipv6_port(addr6, port, e->target);
		return;
	}

	u32 ip = bpf_ntohl(skops->remote_ip4);
	if (ip != 0) {
		format_ip_port(ip, port, e->target);
	} else {
		e->target[0] = '\0';
	}
}

static __always_inline int stamp_socket_cgroup(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;
	if (!sk) {
		return 1;
	}
	sk = bpf_sk_fullsock(sk);
	if (!sk) {
		return 1;
	}

	u64 cgid = bpf_skb_cgroup_id(skb);
	if (cgid == 0) {
		return 1;
	}

	bpf_sk_storage_get(&sk_cgroup_ids, sk, &cgid,
			   BPF_SK_STORAGE_GET_F_CREATE);
	return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_stamp_egress(struct __sk_buff *skb)
{
	return stamp_socket_cgroup(skb);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_stamp_ingress(struct __sk_buff *skb)
{
	return stamp_socket_cgroup(skb);
}

SEC("sockops")
int sockops_rtt(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_ops_cb_flags_set(skops,
					  skops->bpf_sock_ops_cb_flags |
						  BPF_SOCK_OPS_RTT_CB_FLAG);
		return 0;

	case BPF_SOCK_OPS_RTT_CB:
		break;

	default:
		return 0;
	}

	u32 srtt_us = skops->srtt_us;
	if (srtt_us == 0) {
		return 0;
	}

	struct bpf_sock *sk = skops->sk;
	if (!sk) {
		return 0;
	}
	u64 *owner = bpf_sk_storage_get(&sk_cgroup_ids, sk, NULL, 0);
	if (!owner || *owner == 0) {
		return 0;
	}
	u64 cgid = *owner;
	if (!cgroup_allows(cgid)) {
		return 0;
	}

	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}

	e->timestamp = bpf_ktime_get_ns();
	e->cgroup_id = cgid;
	e->pid = 0;
	__builtin_memset(e->comm, 0, sizeof(e->comm));
	e->type = EVENT_TCP_RTT;
	e->latency_ns = (u64)srtt_us * 125;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->details[0] = '\0';

	rtt_fill_target(skops, e);

	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}
