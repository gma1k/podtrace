// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_AGG_H
#define PODTRACE_AGG_H

#include "common.h"
#include "events.h"

#define AGG_SCHEMA        3
#define AGG_SCHEMA_STEPS  (1 << AGG_SCHEMA)

#define AGG_BUCKET_NONE   0xFFFF

struct agg_key {
	u64 cgroup_id;
	u8  peer_addr[16];
	u16 peer_port;
	u8  event_type;
	u8  variant;
	u16 bucket;
	u8  role;
	u8  pad[9];
};

_Static_assert(sizeof(struct agg_key) == 40, "agg_key must match kernelagg.Key");

struct agg_value {
	u64 count;
	u64 sum_ns;
	u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct agg_key);
	__type(value, struct agg_value);
	__uint(max_entries, 65536);
} agg_metrics SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} agg_enabled SEC(".maps");

struct agg_config {
	u32 cgroup_row_budget;
	u32 generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct agg_config);
	__uint(max_entries, 1);
} agg_config SEC(".maps");

struct agg_cgroup_rows_value {
	u32 generation;
	u32 rows;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct agg_cgroup_rows_value);
	__uint(max_entries, 16384);
} agg_cgroup_rows SEC(".maps");

#define AGG_STAT_ROWS_CREATED  0
#define AGG_STAT_PEER_COLLAPSED 1
#define AGG_STAT_COUNT         2

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, AGG_STAT_COUNT);
} agg_stats SEC(".maps");

#define AGG_MODE_OFF    0
#define AGG_MODE_ON     1
#define AGG_MODE_BYPASS 2

static __always_inline u32 agg_mode(void)
{
	u32 zero = 0;
	u32 *mode = bpf_map_lookup_elem(&agg_enabled, &zero);
	if (!mode)
		return AGG_MODE_OFF;
	return *mode;
}

static __always_inline int agg_is_enabled(void)
{
	return agg_mode() != AGG_MODE_OFF;
}

#define AGG_B1 4683695048ULL /* 2^(1/8) = 1.090507733 */
#define AGG_B2 5107605667ULL /* 2^(2/8) = 1.189207115 */
#define AGG_B3 5569883475ULL /* 2^(3/8) = 1.296839555 */
#define AGG_B4 6074001000ULL /* 2^(4/8) = 1.414213562 */
#define AGG_B5 6623745059ULL /* 2^(5/8) = 1.542210825 */
#define AGG_B6 7223245206ULL /* 2^(6/8) = 1.681792831 */
#define AGG_B7 7877004752ULL /* 2^(7/8) = 1.834008086 */

static __always_inline u32 agg_msb(u64 v)
{
	u32 pos = 0;
	u32 shift;

	shift = (v > 0xFFFFFFFFULL) ? 32 : 0; v >>= shift; pos |= shift;
	shift = (v > 0xFFFFULL)     ? 16 : 0; v >>= shift; pos |= shift;
	shift = (v > 0xFFULL)       ?  8 : 0; v >>= shift; pos |= shift;
	shift = (v > 0xFULL)        ?  4 : 0; v >>= shift; pos |= shift;
	shift = (v > 0x3ULL)        ?  2 : 0; v >>= shift; pos |= shift;
	shift = (v > 0x1ULL)        ?  1 : 0;               pos |= shift;
	return pos;
}

static __always_inline u64 agg_scale(u64 ns)
{
	u64 whole = ns / 1000000000ULL;
	u64 rest = ns - whole * 1000000000ULL;

	return ns + whole * 73741824ULL + rest * 73741824ULL / 1000000000ULL;
}

static __always_inline u16 agg_bucket(u64 ns)
{
	u32 msb, sub;
	u64 mantissa;

	if (ns == 0)
		return 0;

	msb = agg_msb(ns);
	if (msb >= 32)
		mantissa = ns >> (msb - 32);
	else
		mantissa = ns << (32 - msb);

	sub = 0;
	sub += (mantissa > AGG_B1) ? 1 : 0;
	sub += (mantissa > AGG_B2) ? 1 : 0;
	sub += (mantissa > AGG_B3) ? 1 : 0;
	sub += (mantissa > AGG_B4) ? 1 : 0;
	sub += (mantissa > AGG_B5) ? 1 : 0;
	sub += (mantissa > AGG_B6) ? 1 : 0;
	sub += (mantissa > AGG_B7) ? 1 : 0;

	return (u16)(msb * AGG_SCHEMA_STEPS + sub);
}

static const struct agg_value agg_value_zero = {};

static __always_inline void agg_key_peer(struct agg_key *key, const struct event *e)
{
	if (e->peer_family == AF_INET6) {
		__builtin_memcpy(key->peer_addr, e->peer_daddr6, sizeof(key->peer_addr));
		return;
	}
	u32 v4 = e->peer_daddr;
	if (v4 == 0)
		return;
	key->peer_addr[10] = 0xff;
	key->peer_addr[11] = 0xff;
	key->peer_addr[12] = (u8)(v4 >> 24);
	key->peer_addr[13] = (u8)(v4 >> 16);
	key->peer_addr[14] = (u8)(v4 >> 8);
	key->peer_addr[15] = (u8)v4;
}

static __always_inline void agg_stat_inc(u32 index)
{
	u64 *count = bpf_map_lookup_elem(&agg_stats, &index);
	if (count)
		*count += 1;
}

static __always_inline int agg_cgroup_over_budget(u64 cgroup_id, const struct agg_config *cfg)
{
	if (!cfg || cfg->cgroup_row_budget == 0)
		return 0;
	struct agg_cgroup_rows_value *rows = bpf_map_lookup_elem(&agg_cgroup_rows, &cgroup_id);
	if (!rows || rows->generation != cfg->generation)
		return 0;
	return rows->rows >= cfg->cgroup_row_budget;
}

static __always_inline void agg_cgroup_row_created(u64 cgroup_id, const struct agg_config *cfg)
{
	agg_stat_inc(AGG_STAT_ROWS_CREATED);
	if (!cfg || cfg->cgroup_row_budget == 0)
		return;
	struct agg_cgroup_rows_value *rows = bpf_map_lookup_elem(&agg_cgroup_rows, &cgroup_id);
	if (rows && rows->generation == cfg->generation) {
		__sync_fetch_and_add(&rows->rows, 1);
		return;
	}
	struct agg_cgroup_rows_value fresh = {
		.generation = cfg->generation,
		.rows = 1,
	};
	bpf_map_update_elem(&agg_cgroup_rows, &cgroup_id, &fresh, BPF_ANY);
}

static __always_inline int agg_key_has_peer(const struct agg_key *key)
{
	const u64 *addr = (const u64 *)key->peer_addr;
	return addr[0] | addr[1] | key->peer_port;
}

static __always_inline int agg_record_in(void *map, u64 cgroup_id, u8 event_type, u8 variant,
					 u8 role, const struct event *peer,
					 u64 latency_ns, u64 bytes, int bucketed,
					 int budgeted)
{
	struct agg_key key = {};
	struct agg_value *val;

	if (cgroup_id == 0)
		return 0;

	key.cgroup_id = cgroup_id;
	if (peer) {
		agg_key_peer(&key, peer);
		key.peer_port = peer->peer_dport;
	}
	key.event_type = event_type;
	key.variant = variant;
	key.role = role;
	key.bucket = bucketed ? agg_bucket(agg_scale(latency_ns)) : AGG_BUCKET_NONE;

	val = bpf_map_lookup_elem(map, &key);
	if (!val) {
		const struct agg_config *cfg = NULL;
		if (budgeted) {
			u32 zero = 0;
			cfg = bpf_map_lookup_elem(&agg_config, &zero);
			if (agg_key_has_peer(&key) && agg_cgroup_over_budget(cgroup_id, cfg)) {
				__builtin_memset(key.peer_addr, 0, sizeof(key.peer_addr));
				key.peer_port = 0;
				agg_stat_inc(AGG_STAT_PEER_COLLAPSED);
				val = bpf_map_lookup_elem(map, &key);
			}
		}
		if (!val) {
			if (bpf_map_update_elem(map, &key, &agg_value_zero, BPF_NOEXIST) == 0 && budgeted)
				agg_cgroup_row_created(cgroup_id, cfg);
			val = bpf_map_lookup_elem(map, &key);
			if (!val)
				return 0;
		}
	}

	val->count += 1;
	if (bucketed)
		val->sum_ns += latency_ns;
	val->bytes += bytes;
	return 1;
}

static __always_inline int agg_record(u64 cgroup_id, u8 event_type, u8 variant,
				      u8 role, const struct event *peer,
				      u64 latency_ns, u64 bytes, int bucketed)
{
	if (!agg_is_enabled())
		return 0;
	return agg_record_in(&agg_metrics, cgroup_id, event_type, variant,
			     role, peer, latency_ns, bytes, bucketed, 1);
}

#define AGG_VARIANT(proto, status_class, is_error) \
	((u8)(((proto) & 0x7) | (((status_class) & 0x7) << 3) | (((is_error) & 0x1) << 6)))

static __noinline int agg_from_event(struct event *e, s32 status_num)
{
	u8 variant = 0;
	u8 role = 0;
	int bucketed = 1;
	u64 bytes = 0;
	u32 status_class = 0;
	u32 is_error = 0;

	if (!e)
		return 0;

	if (status_num >= 100 && status_num <= 599)
		status_class = (u32)(status_num / 100);
	if (e->error != 0)
		is_error = 1;

	switch (e->type) {
	case EVENT_TCP_SEND:
	case EVENT_TCP_RECV:
	case EVENT_UDP_SEND:
	case EVENT_UDP_RECV:
		bytes = e->bytes;
		break;

	case EVENT_SCHED_SWITCH:
		variant = AGG_VARIANT(e->tcp_state, 0, 0);
		break;

	case EVENT_DNS: {
		u32 class = dns_answer_class(e->dns_transport, e->error);

		variant = AGG_VARIANT(e->dns_transport, class, dns_class_failed(class));
		break;
	}

	case EVENT_DNS_QUERY:
	case EVENT_TLS_HANDSHAKE:
	case EVENT_DB_ACQUIRE:
	case EVENT_LOCK_CONTENTION:
	case EVENT_TCP_RTT:
		break;

	case EVENT_TCP_RETRANS:
		bucketed = 0;
		break;

	case EVENT_CONNECT:
		variant = AGG_VARIANT(e->tcp_state, 0, is_error);
		bucketed = 0;
		break;

	case EVENT_CONNECT_RESULT:
		bucketed = 0;
		break;

	case EVENT_NET_DEV_ERROR:
		bytes = e->bytes;
		bucketed = 0;
		break;

	case EVENT_READ:
	case EVENT_WRITE:
		bytes = e->bytes;
		break;

	case EVENT_OPEN:
		if (e->error == -ENOENT)
			is_error = 0;
		break;

	case EVENT_FSYNC:
	case EVENT_CLOSE:
	case EVENT_UNLINK:
	case EVENT_RENAME:
		break;

	case EVENT_HTTP_RESP:
	case EVENT_HTTP3:
	case EVENT_GRPC_METHOD:
	case EVENT_FASTCGI_RESPONSE:
	case EVENT_REDIS_CMD:
	case EVENT_MEMCACHED_CMD:
	case EVENT_KAFKA_PRODUCE:
	case EVENT_KAFKA_FETCH:
	case EVENT_DB_QUERY:
		if (status_class >= 5)
			is_error = 1;
		variant = AGG_VARIANT(e->tcp_state, status_class, is_error);
		if (e->type == EVENT_HTTP_RESP || e->type == EVENT_GRPC_METHOD)
			role = (u8)(e->tcp_state & HTTP_ROLE_MASK);
		break;

	default:
		return 0;
	}

	if (variant == 0)
		variant = AGG_VARIANT(0, status_class, is_error);

	return agg_record(e->cgroup_id, (u8)e->type, variant,
			  role, e, e->latency_ns, bytes, bucketed);
}

static __always_inline int event_buf_intact(struct event *e);

static __always_inline int agg_absorbed_checked(struct event *e, s32 status_num, int tracked)
{
	if (tracked && !event_buf_intact(e)) {
		e->agg_recorded = 0;
		return 1;
	}
	int recorded = agg_from_event(e, status_num);

	e->agg_recorded = (u8)recorded;
	if (!recorded)
		return 0;
	return agg_mode() == AGG_MODE_BYPASS;
}

static __always_inline int agg_absorbed(struct event *e, s32 status_num)
{
	return agg_absorbed_checked(e, status_num, 1);
}

static __always_inline int agg_absorbed_untracked(struct event *e, s32 status_num)
{
	return agg_absorbed_checked(e, status_num, 0);
}

#endif /* PODTRACE_AGG_H */
