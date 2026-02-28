// SPDX-License-Identifier: GPL-2.0
/*
 * Kafka tracing via librdkafka uprobes.
 *
 * Hooks:
 *   uprobe/rd_kafka_topic_new     — rd_kafka_topic_t *rd_kafka_topic_new(
 *                                       rd_kafka_t *rk, const char *topic,
 *                                       rd_kafka_topic_conf_t *conf)
 *   uretprobe/rd_kafka_topic_new  — captures topic_t* → name mapping
 *
 *   uprobe/rd_kafka_produce       — int rd_kafka_produce(
 *                                       rd_kafka_topic_t *rkt, int32_t partition,
 *                                       int msgflags, void *payload, size_t len, ...)
 *   uretprobe/rd_kafka_produce
 *
 *   uprobe/rd_kafka_consumer_poll — rd_kafka_message_t *rd_kafka_consumer_poll(
 *                                       rd_kafka_t *rk, int timeout_ms)
 *   uretprobe/rd_kafka_consumer_poll
 *
 * Field mapping:
 *   target   = "broker" (not available from librdkafka uprobes without deep struct read)
 *   details  = topic name
 *   bytes    = payload size (produce) or message len (fetch)
 *   error    = return code
 *   latency_ns = call duration
 */

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

/* -----------------------------------------------------------------------
 * rd_kafka_topic_new — build topic_t* → name mapping
 * -----------------------------------------------------------------------
 * Signature: rd_kafka_topic_t *rd_kafka_topic_new(rd_kafka_t *rk,
 *                const char *topic, rd_kafka_topic_conf_t *conf)
 * PARM2 = const char *topic (topic name string)
 */
SEC("uprobe/rd_kafka_topic_new")
int uprobe_rd_kafka_topic_new(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	const char *topic = (const char *)PT_REGS_PARM2(ctx);
	if (!topic)
		return 0;

	char buf[MAX_STRING_LEN] = {};
	bpf_probe_read_user_str(buf, sizeof(buf), topic);
	bpf_map_update_elem(&kafka_topic_tmp, &key, buf, BPF_ANY);
	return 0;
}

SEC("uretprobe/rd_kafka_topic_new")
int uretprobe_rd_kafka_topic_new(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	/* Return value = rd_kafka_topic_t* */
	u64 topic_ptr = (u64)PT_REGS_RC(ctx);
	if (!topic_ptr) {
		bpf_map_delete_elem(&kafka_topic_tmp, &key);
		return 0;
	}

	char *name = bpf_map_lookup_elem(&kafka_topic_tmp, &key);
	if (name) {
		bpf_map_update_elem(&kafka_topic_names, &topic_ptr, name, BPF_ANY);
		bpf_map_delete_elem(&kafka_topic_tmp, &key);
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * rd_kafka_produce
 * -----------------------------------------------------------------------
 * Signature: int rd_kafka_produce(rd_kafka_topic_t *rkt, int32_t partition,
 *                int msgflags, void *payload, size_t len, ...)
 * PARM1 = rkt, PARM5 = len
 */
SEC("uprobe/rd_kafka_produce")
int uprobe_rd_kafka_produce(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts  = bpf_ktime_get_ns();

	u64 rkt_ptr = (u64)PT_REGS_PARM1(ctx);
	u64 payload_len = (u64)PT_REGS_PARM5(ctx);

	/* Copy topic name through a properly-sized stack buffer.
	 * The verifier requires the value pointer passed to bpf_map_update_elem
	 * to point to at least value_size (MAX_STRING_LEN) bytes on the stack. */
	char topic_buf[MAX_STRING_LEN] = {};
	char *topic = bpf_map_lookup_elem(&kafka_topic_names, &rkt_ptr);
	if (topic)
		bpf_probe_read_kernel_str(topic_buf, sizeof(topic_buf), topic);
	bpf_map_update_elem(&redis_cmds, &key, topic_buf, BPF_ANY);

	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	if (payload_len > 0 && payload_len < MAX_BYTES_THRESHOLD)
		bpf_map_update_elem(&proto_bytes, &key, &payload_len, BPF_ANY);
	return 0;
}

SEC("uretprobe/rd_kafka_produce")
int uretprobe_rd_kafka_produce(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts)
		return 0;

	u64 latency = calc_latency(*start_ts);

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		bpf_map_delete_elem(&redis_cmds, &key);
		bpf_map_delete_elem(&proto_bytes, &key);
		return 0;
	}

	e->timestamp  = bpf_ktime_get_ns();
	e->pid        = pid;
	e->type       = EVENT_KAFKA_PRODUCE;
	e->latency_ns = latency;
	e->error      = (s32)PT_REGS_RC(ctx);  /* 0 = RD_KAFKA_RESP_ERR_NO_ERROR */
	e->tcp_state  = 0;
	e->target[0]  = '\0';  /* broker not directly available */

	u64 *bptr = bpf_map_lookup_elem(&proto_bytes, &key);
	e->bytes = bptr ? *bptr : 0;

	/* Topic name stored in redis_cmds map (reused to avoid extra map) */
	char *topic = bpf_map_lookup_elem(&redis_cmds, &key);
	if (topic)
		bpf_probe_read_kernel_str(e->details, sizeof(e->details), topic);
	else
		e->details[0] = '\0';

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);

	bpf_map_delete_elem(&start_times, &key);
	bpf_map_delete_elem(&redis_cmds, &key);
	bpf_map_delete_elem(&proto_bytes, &key);
	return 0;
}

/* -----------------------------------------------------------------------
 * rd_kafka_consumer_poll
 * -----------------------------------------------------------------------
 * Signature: rd_kafka_message_t *rd_kafka_consumer_poll(rd_kafka_t *rk,
 *                int timeout_ms)
 * Returns NULL if no message available (timeout).
 * rd_kafka_message_t layout (first fields):
 *   err       rd_kafka_resp_err_t (int32) at offset 0
 *   rkt       rd_kafka_topic_t*           at offset 8  (pointer-aligned)
 *   partition int32_t                     at offset 16
 *   payload   void*                       at offset 24
 *   len       size_t                      at offset 32
 */
SEC("uprobe/rd_kafka_consumer_poll")
int uprobe_rd_kafka_consumer_poll(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts  = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/rd_kafka_consumer_poll")
int uretprobe_rd_kafka_consumer_poll(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);

	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts)
		return 0;

	u64 latency = calc_latency(*start_ts);

	/* Return value = rd_kafka_message_t* (NULL = no message / timeout) */
	u64 msg_ptr = (u64)PT_REGS_RC(ctx);
	if (!msg_ptr) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}

	e->timestamp  = bpf_ktime_get_ns();
	e->pid        = pid;
	e->type       = EVENT_KAFKA_FETCH;
	e->latency_ns = latency;
	e->tcp_state  = 0;
	e->target[0]  = '\0';

	/* Read rd_kafka_message_t fields:
	 * offset 0  = err (int32) — wrap in s32
	 * offset 8  = rkt (pointer to topic handle)
	 * offset 32 = len (size_t) */
	s32 msg_err = 0;
	u64 rkt_ptr = 0;
	u64 msg_len = 0;

	bpf_probe_read_user(&msg_err, sizeof(msg_err), (void *)msg_ptr);
	bpf_probe_read_user(&rkt_ptr, sizeof(rkt_ptr), (void *)(msg_ptr + 8));
	bpf_probe_read_user(&msg_len, sizeof(msg_len), (void *)(msg_ptr + 32));

	e->error = msg_err;
	e->bytes = (msg_len < MAX_BYTES_THRESHOLD) ? msg_len : 0;

	/* Topic name from previously mapped rkt_ptr */
	if (rkt_ptr) {
		char *topic = bpf_map_lookup_elem(&kafka_topic_names, &rkt_ptr);
		if (topic)
			bpf_probe_read_kernel_str(e->details, sizeof(e->details), topic);
		else
			e->details[0] = '\0';
	} else {
		e->details[0] = '\0';
	}

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);

	bpf_map_delete_elem(&start_times, &key);
	return 0;
}
