// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#define RESOURCE_CPU    0
#define RESOURCE_MEMORY 1
#define RESOURCE_IO     2

static inline u32 calculate_utilization(u64 usage, u64 limit) {
    if (limit == 0 || limit == ~0ULL) {
        return 0;
    }
    if (usage > limit) {
        return 100;
    }
    u64 percent = (usage * 100) / limit;
    return (u32)(percent > 100 ? 100 : percent);
}

/*
 * check_alert_threshold — returns alert level (0=none, 1=warn, 2=crit, 3=emerg).
 * Thresholds are read from the alert_thresholds BPF map so Go can configure them
 * at runtime (PODTRACE_ALERT_WARN_PCT / _CRIT_PCT / _EMERG_PCT env vars).
 * Falls back to 80/90/95 if the map is unset.
 */
static inline u32 check_alert_threshold(u32 utilization) {
    u32 key;

    key = 2;
    u32 *t_emerg = bpf_map_lookup_elem(&alert_thresholds, &key);
    u32 emerg = (t_emerg && *t_emerg > 0) ? *t_emerg : 95;

    key = 1;
    u32 *t_crit = bpf_map_lookup_elem(&alert_thresholds, &key);
    u32 crit = (t_crit && *t_crit > 0) ? *t_crit : 90;

    key = 0;
    u32 *t_warn = bpf_map_lookup_elem(&alert_thresholds, &key);
    u32 warn = (t_warn && *t_warn > 0) ? *t_warn : 80;

    if (utilization >= emerg) return 3;
    if (utilization >= crit)  return 2;
    if (utilization >= warn)  return 1;
    return 0;
}

static inline void emit_resource_alert(u64 cgroup_id, u32 resource_type, u32 utilization, u64 limit, u64 usage) {
    struct event *e = get_event_buf();
    if (!e) {
        return;
    }
    
    e->timestamp = bpf_ktime_get_ns();
    e->pid = 0;
    e->type = EVENT_RESOURCE_LIMIT;
    e->latency_ns = 0;
    e->error = (s32)utilization;
    e->bytes = usage;
    e->tcp_state = resource_type;
    e->target[0] = '\0';
    
    char *details = e->details;
    u32 idx = 0;
    u32 max_idx = MAX_STRING_LEN - 1;
    
    const char *resource_names[] = {"CPU", "MEM", "IO"};
    if (resource_type < 3) {
        const char *name = resource_names[resource_type];
        for (int i = 0; name[i] != '\0' && idx < max_idx; i++) {
            details[idx++] = name[i];
        }
    }
    
    if (idx < max_idx) details[idx++] = ':';
    
    if (utilization >= 100 && idx < max_idx - 2) {
        details[idx++] = '1';
        details[idx++] = '0';
        details[idx++] = '0';
    } else if (utilization >= 10 && idx < max_idx - 1) {
        details[idx++] = '0' + (utilization / 10);
        details[idx++] = '0' + (utilization % 10);
    } else if (idx < max_idx) {
        details[idx++] = '0' + utilization;
    }
    
    if (idx < max_idx) details[idx++] = '%';
    details[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
    
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    
    u32 alert_level = check_alert_threshold(utilization);
    if (alert_level > 0) {
        bpf_map_update_elem(&cgroup_alerts, &cgroup_id, &alert_level, BPF_ANY);
    } else {
        bpf_map_delete_elem(&cgroup_alerts, &cgroup_id);
    }
}