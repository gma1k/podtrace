package ebpf

import (
	"strings"
	"testing"
)

func TestOnlyTheSharedMetricsMapIsRowBudgeted(t *testing.T) {
	agg := bpfSource(t, "agg.h")
	if !strings.Contains(functionBody(t, agg, "agg_record"), "role, peer, latency_ns, bytes, bucketed, 1)") {
		t.Error("agg_record must budget rows of the shared agg_metrics map per cgroup")
	}
	fs := bpfSource(t, "filesystem.h")
	if !strings.Contains(fs, "agg_record_in(&fs_fast_ops, cgroup_id, (u8)type, variant, 0, NULL, latency_ns, bytes, 1, 0);") {
		t.Error("the peer-less fs_fast_ops map must not consume or check the per-cgroup row budget")
	}
}

func TestTheRowBudgetFoldsOnlyTheHitThatWouldCreateAPeerRow(t *testing.T) {
	body := functionBody(t, bpfSource(t, "agg.h"), "agg_record_in")
	miss := strings.Index(body, "if (!val) {")
	check := strings.Index(body, "agg_key_has_peer(&key) && agg_cgroup_over_budget(cgroup_id, cfg)")
	create := strings.Index(body, "bpf_map_update_elem(map, &key, &agg_value_zero, BPF_NOEXIST) == 0 && budgeted")
	if miss < 0 || check < miss || create < check {
		t.Fatal("the budget must be checked only on a miss, before a new row is created, and only a created row may count against it")
	}
	if !strings.Contains(body, "agg_cgroup_row_created(cgroup_id, cfg)") {
		t.Error("a created row is not counted against its cgroup's budget")
	}
}

func TestTheRowBudgetResetsByGenerationNotByWalkingTheMap(t *testing.T) {
	agg := bpfSource(t, "agg.h")
	for _, fn := range []string{"agg_cgroup_over_budget", "agg_cgroup_row_created"} {
		if !strings.Contains(functionBody(t, agg, fn), "generation") {
			t.Errorf("%s must treat a row count from an earlier generation as zero", fn)
		}
	}
	if !strings.Contains(functionBody(t, agg, "agg_cgroup_row_created"), "agg_stat_inc(AGG_STAT_ROWS_CREATED)") {
		t.Error("every created row must be counted, or evictions cannot be estimated")
	}
}

func TestADNSAnswerMustComeFromTheServerToTheQueryingPort(t *testing.T) {
	text := bpfSource(t, "dns.c")
	ingress := functionBody(t, text, "dns_ingress")
	match := strings.Index(ingress, "dns_response_matches_query(skb, q, is_v6, dport)")
	reserve := strings.Index(ingress, "bpf_ringbuf_reserve(&events")
	if match < 0 || reserve < 0 || match > reserve {
		t.Fatal("dns_ingress must bind a response to its query before recording it")
	}
	matches := functionBody(t, text, "dns_response_matches_query")
	if !strings.Contains(matches, "q->client_port != dport") {
		t.Error("a response to another socket in the pod must not match the query")
	}
	if !strings.Contains(matches, "dns_server_matches(skb, q, is_v6, 12, 8)") {
		t.Error("a response from an address the query never went to must not match it")
	}
}

func TestAResentDNSQueryFollowsItsLatestSocketAndServer(t *testing.T) {
	body := functionBody(t, bpfSource(t, "dns.c"), "dns_egress_run")
	if !strings.Contains(body, "q.client_port = sport;") {
		t.Error("a new query must record the port its answer will arrive on")
	}
	resend := strings.Index(body, "if (sent) {")
	if resend < 0 {
		t.Fatal("dns_egress_run no longer handles a resent query")
	}
	tail := body[resend:]
	for _, want := range []string{"sent->client_port = sport;", "sent->multi_server = 1;"} {
		if !strings.Contains(tail, want) {
			t.Errorf("a resend must do %q, or an answer from a fallback nameserver is dropped", want)
		}
	}
}
