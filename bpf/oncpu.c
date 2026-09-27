// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "helpers.h"
#include "oncpu.h"

static __always_inline void oncpu_count_lost(u32 reason)
{
	u64 *lost = bpf_map_lookup_elem(&oncpu_lost, &reason);
	if (lost)
		(*lost)++;
}

SEC("perf_event")
int perf_event_oncpu_sample(void *ctx)
{
	if (!oncpu_is_enabled())
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	if ((pid_tgid >> 32) == 0)
		return 0;

	u64 cgid = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&target_cgroup_ids, &cgid))
		return 0;

	long stack_id = bpf_get_stackid(ctx, &oncpu_stacks, BPF_F_USER_STACK);
	if (stack_id < 0) {
		oncpu_count_lost(ONCPU_LOST_STACK);
		return 0;
	}

	struct oncpu_key key = {};
	key.cgroup_id = cgid;
	key.correlation_id = oncpu_active_request((u32)pid_tgid);
	key.pid = agent_ns_tgid();
	key.stack_id = (u32)stack_id;

	u64 *count = bpf_map_lookup_elem(&oncpu_counts, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return 0;
	}
	u64 one = 1;
	if (bpf_map_update_elem(&oncpu_counts, &key, &one, BPF_NOEXIST) == 0)
		return 0;
	count = bpf_map_lookup_elem(&oncpu_counts, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	else
		oncpu_count_lost(ONCPU_LOST_FULL);
	return 0;
}
