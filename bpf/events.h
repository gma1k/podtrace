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
	EVENT_UNLINK,   /* 29: file unlinked via vfs_unlink */
	EVENT_RENAME,   /* 30: file renamed via vfs_rename */
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
	/* V4 additions — populated under PODTRACE_VMLINUX_FROM_BTF */
	u32 net_ns_id;  /* network namespace inum (0 if BTF unavailable) */
	u32 _pad2;      /* explicit padding to keep struct 8-byte aligned */
};

#endif
