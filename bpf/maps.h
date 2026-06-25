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

enum probe_pair {
	PAIR_TCP_CONNECT_V4 = 1,
	PAIR_TCP_CONNECT_V6,
	PAIR_TCP_SENDMSG,
	PAIR_TCP_RECVMSG,
	PAIR_UDP_SENDMSG,
	PAIR_UDP_RECVMSG,
	PAIR_GETADDRINFO,
	PAIR_HTTP_REQUEST,
	PAIR_HTTP_RESPONSE,
	PAIR_PQEXEC,
	PAIR_MYSQL_QUERY,
	PAIR_SSL_CONNECT,
	PAIR_SSL_ACCEPT,
	PAIR_SSL_DO_HANDSHAKE,
	PAIR_GNUTLS_HANDSHAKE,
	PAIR_MBEDTLS_HANDSHAKE,
	PAIR_OPENAT,
	PAIR_VFS_UNLINK,
	PAIR_VFS_RENAME,
	PAIR_VFS_READ,
	PAIR_VFS_WRITE,
	PAIR_VFS_FSYNC,
	PAIR_FUTEX,
	PAIR_PTHREAD_MUTEX,
	PAIR_REDIS_COMMAND,
	PAIR_REDIS_COMMAND_ARGV,
	PAIR_MEMCACHED,
	PAIR_KAFKA_TOPIC_NEW,
	PAIR_KAFKA_PRODUCE,
	PAIR_KAFKA_POLL,
};

struct pair_key {
	u64 pid_tgid;
	u32 pair;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, u64);
} start_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} dns_targets SEC(".maps");

struct dns_flow_key {
	u64 cgroup_id;
	u32 txid;
	u32 _pad;
};

struct dns_query_state {
	u64 ts_ns;
	u32 pid;
	u32 qtype;
	u32 server_ip;
	u8 transport;
	u8 _pad[3];
	char comm[COMM_LEN];
	char name[MAX_STRING_LEN];
	u8 server_ip6[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct dns_flow_key);
	__type(value, struct dns_query_state);
} dns_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, char[MAX_STRING_LEN]);
} dns_resolved SEC(".maps");

struct dns_v6key {
	u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dns_v6key);
	__type(value, char[MAX_STRING_LEN]);
} dns_resolved6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} dns_drops SEC(".maps");

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
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} lock_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} db_queries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
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

#define RESOURCE_CPU    0
#define RESOURCE_MEMORY 1
#define RESOURCE_IO     2

struct resource_key {
	u64 cgroup_id;
	u32 resource_type;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct resource_key);
	__type(value, struct resource_limit);
} cgroup_limits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct resource_key);
	__type(value, u32);
} cgroup_alerts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} target_cgroup_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} cgroup_filter_enabled SEC(".maps");

struct cpu_quota {
	u64 quota_us;
	u64 period_us;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct cpu_quota);
} cgroup_cpu_quota SEC(".maps");

struct cpu_window {
	u64 window_start_ns;
	u64 runtime_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct cpu_window);
} cgroup_cpu_window SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u64);
} sched_in_ts SEC(".maps");

struct connect_addr {
	u16 family;
	u16 port_be;
	u32 addr_be;
	u8 addr6[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, struct connect_addr);
} connect_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u64);
} sched_out_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u64);
} sched_pending_blocked SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} page_fault_seq SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, u32);
	__type(value, u32);
} alert_thresholds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} event_buf SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} recvmsg_args SEC(".maps");

struct fcgi_pending {
	u32 request_id;
	u32 expected_body_bytes;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct fcgi_pending);
} fastcgi_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} redis_cmds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} memcached_ops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} grpc_methods SEC(".maps");

struct http_req {
	u64 start_ns;
	char endpoint[MAX_STRING_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct http_req);
} http_reqs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} http_recv_base SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} kafka_topic_names SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} kafka_topic_tmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, u64);
} proto_bytes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct stack_trace_t);
} stack_buf SEC(".maps");

#endif
