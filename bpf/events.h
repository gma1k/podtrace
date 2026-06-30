// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_EVENTS_H
#define PODTRACE_EVENTS_H

#include "common.h"

enum event_type {
	EVENT_DNS,
	EVENT_CONNECT,
	EVENT_TCP_SEND,
	EVENT_TCP_RECV,
	EVENT_WRITE,
	EVENT_READ,
	EVENT_FSYNC,
	EVENT_SCHED_SWITCH,
	EVENT_TCP_STATE,
	EVENT_PAGE_FAULT,
	EVENT_OOM_KILL,
	EVENT_UDP_SEND,
	EVENT_UDP_RECV,
	EVENT_HTTP_REQ,
	EVENT_HTTP_RESP,
	EVENT_LOCK_CONTENTION,
	EVENT_TCP_RETRANS,
	EVENT_NET_DEV_ERROR,
	EVENT_DB_QUERY,
	EVENT_EXEC,
	EVENT_FORK,
	EVENT_OPEN,
	EVENT_CLOSE,
	EVENT_TLS_HANDSHAKE,
	EVENT_TLS_ERROR,
	EVENT_RESOURCE_LIMIT,
	EVENT_POOL_ACQUIRE,
	EVENT_POOL_RELEASE,
	EVENT_POOL_EXHAUSTED,
	EVENT_UNLINK,
	EVENT_RENAME,
	EVENT_REDIS_CMD,
	EVENT_MEMCACHED_CMD,
	EVENT_FASTCGI_REQUEST,
	EVENT_FASTCGI_RESPONSE,
	EVENT_GRPC_METHOD,
	EVENT_KAFKA_PRODUCE,
	EVENT_KAFKA_FETCH,
	EVENT_DNS_QUERY,
	EVENT_AF_ALG,
	EVENT_HTTP3,
};

struct event {
	u64 timestamp;
	u32 pid;
	u32 type;
	u64 latency_ns;
	s32 error;
	u64 bytes;
	u32 tcp_state;
	u64 stack_key;
	u64 cgroup_id;
	char comm[COMM_LEN];
	char target[MAX_STRING_LEN];
	char details[MAX_STRING_LEN];
	u32 net_ns_id;
	u32 _pad2;
	u32 dns_server_ip;
	u8  dns_transport;
	u8  _pad3[3];
	u8  dns_server_ip6[16];
	u32 peer_saddr;
	u32 peer_daddr;
	u16 peer_sport;
	u16 peer_dport;
	u8  peer_family;
	u8  _pad4[3];
	u8  peer_saddr6[16];
	u8  peer_daddr6[16];
};

#define H2_HDR_FRAG_MAX 1024

#define H2_DIR_EGRESS  0
#define H2_DIR_INGRESS 1
#define H2_HDR_FLAG_END_HEADERS  0x1
#define H2_HDR_FLAG_CONTINUATION 0x2
#define H2_HDR_FLAG_CLOSE        0x4

struct h2_hdr_record {
	u64 conn_id;
	u64 timestamp;
	u64 cgroup_id;
	u32 pid;
	u32 seq;
	u32 stream_id;
	u16 frag_len;
	u8  direction;
	u8  transport;
	u8  flags;
	u8  _pad[7];
	u32 peer_saddr;
	u32 peer_daddr;
	u16 peer_sport;
	u16 peer_dport;
	u8  peer_family;
	u8  _pad5[3];
	u8  peer_saddr6[16];
	u8  peer_daddr6[16];
};

#define H3_TXN_METHOD_MAX 16
#define H3_TXN_PATH_MAX   256

struct h3_field_offsets {
	u32 method;
	u32 url;
	u32 path;
	u32 status;
};

#define H3_TXN_TP_MAX 64

struct h3_txn_record {
	u64 timestamp;
	u64 latency_ns;
	u64 cgroup_id;
	u32 pid;
	u16 status;
	u8  is_client;
	u8  method_len;
	u16 path_len;
	u8  tp_len;
	u8  _pad[5];
	char method[H3_TXN_METHOD_MAX];
	char path[H3_TXN_PATH_MAX];
	char traceparent[H3_TXN_TP_MAX];
};

#endif
