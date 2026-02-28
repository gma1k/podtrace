// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_MAPS_H
#define PODTRACE_MAPS_H

#include "common.h"
#include "events.h"

struct stack_trace_t {
	u64 ips[MAX_STACK_DEPTH];
	u32 nr;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} start_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} dns_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} socket_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} tcp_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, u64);
	__type(value, struct stack_trace_t);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} lock_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} db_queries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} syscall_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} tls_handshakes SEC(".maps");

struct resource_limit {
	u64 limit_bytes;
	u64 usage_bytes;
	u64 last_update_ns;
	u32 resource_type;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct resource_limit);
} cgroup_limits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u32);
} cgroup_alerts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} target_cgroup_id SEC(".maps");

struct pool_state {
	u64 last_use_ns;
	u32 connection_id;
	u32 in_use;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct pool_state);
} pool_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} pool_acquire_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u32);
} pool_db_types SEC(".maps");

/* alert_thresholds[0]=warn%, [1]=crit%, [2]=emerg% — written from Go at startup */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, u32);
	__type(value, u32);
} alert_thresholds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} event_buf SEC(".maps");

/* --- PROTOCOL ADAPTER MAPS (Redis, Memcached, FastCGI, gRPC, Kafka) --- */

/* FastCGI request state — keyed by pid<<32|requestId (BTF-only) */
struct fastcgi_req {
	u64 start_ns;
	char uri[MAX_STRING_LEN];
	char method[16];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct fastcgi_req);
} fastcgi_reqs SEC(".maps");

/* Saved msghdr* for unix_stream_recvmsg kretprobe (BTF-only FastCGI) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);  /* msghdr pointer cast to u64 */
} recvmsg_args SEC(".maps");

/* Redis: pid<<32|tid → first word of redisCommand format string */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} redis_cmds SEC(".maps");

/* Memcached: pid<<32|tid → "get/set/del key" operation string */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} memcached_ops SEC(".maps");

/* gRPC: pid<<32|tid → "/Service/Method" path (BTF-only h2c inspection) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} grpc_methods SEC(".maps");

/* Kafka: rd_kafka_topic_t* → topic name string (populated by rd_kafka_topic_new) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u64);  /* rd_kafka_topic_t* cast to u64 */
	__type(value, char[MAX_STRING_LEN]);
} kafka_topic_names SEC(".maps");

/* Kafka: pid<<32|tid → topic name (temporary during rd_kafka_topic_new call) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} kafka_topic_tmp SEC(".maps");

/* Shared pending byte count for protocol uprobes (Redis, Memcached, Kafka) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);  /* pid<<32|tid */
	__type(value, u64); /* byte count captured at uprobe entry */
} proto_bytes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct stack_trace_t);
} stack_buf SEC(".maps");

#endif
