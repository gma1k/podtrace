package ebpf

import (
	"strings"
	"testing"
)

func TestAggregationMapsAreSharedAcrossCPUs(t *testing.T) {
	for _, m := range []struct{ file, name string }{
		{"agg.h", "agg_metrics"},
		{"filesystem.h", "fs_fast_ops"},
	} {
		block, ok := mapBlock(bpfSource(t, m.file), m.name)
		if !ok {
			t.Fatalf("map %s not found in %s", m.name, m.file)
		}
		if !strings.Contains(block, "__uint(type, BPF_MAP_TYPE_LRU_HASH);") {
			t.Errorf("%s must be one shared LRU hash; a per-CPU value preallocates every row once per possible CPU", m.name)
		}
	}
	record := functionBody(t, bpfSource(t, "agg.h"), "agg_record_in")
	for _, want := range []string{
		"__sync_fetch_and_add(&val->count, 1);",
		"__sync_fetch_and_add(&val->sum_ns, latency_ns);",
		"__sync_fetch_and_add(&val->bytes, bytes);",
	} {
		if !strings.Contains(record, want) {
			t.Errorf("agg_record_in lacks %q; CPUs share the row, so a plain add loses updates", want)
		}
	}
	for _, racy := range []string{"val->count +=", "val->sum_ns +=", "val->bytes +="} {
		if strings.Contains(record, racy) {
			t.Errorf("agg_record_in still does %q", racy)
		}
	}
}

func TestUSDTSpecsAreNeverEvicted(t *testing.T) {
	block, ok := mapBlock(bpfSource(t, "maps.h"), "usdt_probes")
	if !ok {
		t.Fatal("usdt_probes not found")
	}
	if !strings.Contains(block, "__uint(type, BPF_MAP_TYPE_HASH);") {
		t.Error("usdt_probes must be a plain hash: an LRU silently evicts the live spec another pod's probe reads")
	}
}

func TestOneCgroupCannotEvictAnotherCgroupsDNSQueries(t *testing.T) {
	maps := bpfSource(t, "maps.h")
	if !strings.Contains(maps, "#define DNS_INFLIGHT_CGROUP_BUDGET 4096") {
		t.Error("the per-cgroup in-flight budget must stay at the old map size, so no pod tracks fewer queries than before")
	}
	inflight, ok := mapBlock(maps, "dns_inflight")
	if !ok || !strings.Contains(inflight, "__uint(max_entries, 4 * DNS_INFLIGHT_CGROUP_BUDGET);") {
		t.Error("dns_inflight must hold several cgroups at their full budget")
	}
	counts, ok := mapBlock(maps, "dns_inflight_cgroup")
	if !ok || !strings.Contains(counts, "__type(value, s32);") {
		t.Error("dns_inflight_cgroup must count in-flight queries per cgroup")
	}

	dns := bpfSource(t, "dns.c")
	egress := functionBody(t, dns, "dns_egress_run")
	admit := strings.Index(egress, "if (!dns_inflight_admits(key.cgroup_id)) {\n\t\tdns_drop_inc();")
	insert := strings.Index(egress, "bpf_map_update_elem(&dns_inflight, &key, &q, BPF_NOEXIST)")
	if admit < 0 || insert < 0 || admit > insert {
		t.Error("a cgroup at its budget must be refused, and counted as a drop, before it can evict anything")
	}
	for _, want := range []string{
		"if (err == 0)\n\t\t\tdns_inflight_count(key.cgroup_id, 1);",
		"else if (err != -EEXIST)\n\t\t\tdns_drop_inc();",
	} {
		if !strings.Contains(egress, want) {
			t.Errorf("dns_egress_run lacks %q", want)
		}
	}
	ingress := functionBody(t, dns, "dns_ingress")
	if strings.Contains(ingress, "bpf_map_delete_elem(&dns_inflight") {
		t.Error("dns_ingress must remove answered queries through dns_inflight_forget so the count follows")
	}
	if strings.Count(ingress, "dns_inflight_forget(&key);") != 3 {
		t.Errorf("every exit of dns_ingress that drops the query must use dns_inflight_forget, found %d",
			strings.Count(ingress, "dns_inflight_forget(&key);"))
	}
	forget := functionBody(t, dns, "dns_inflight_forget")
	if !strings.Contains(forget, "if (bpf_map_delete_elem(&dns_inflight, key) == 0)\n\t\tdns_inflight_count(key->cgroup_id, -1);") {
		t.Error("only the delete that removed the entry may lower the count")
	}
}

func TestAFullDNSPayloadRingIsCountedAsADrop(t *testing.T) {
	body := functionBody(t, bpfSource(t, "dns.c"), "emit_dns_payload")
	if !strings.Contains(body, "if (bpf_ringbuf_output(&dns_payload_events, scr, sizeof(scr->rec) + avail, 0) < 0)\n\t\tdns_drop_inc();") {
		t.Error("emit_dns_payload loses the lookup without a drop count when the payload ring is full")
	}
}

func TestThreadCreationIsNotReportedAsAFork(t *testing.T) {
	body := functionBody(t, bpfSource(t, "syscalls.c"), "raw_tracepoint_sched_process_fork")
	leader := strings.Index(body, "if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))\n\t\treturn 0;")
	buffer := strings.Index(body, "get_event_buf()")
	if leader < 0 || buffer < 0 || leader > buffer {
		t.Error("raw_tracepoint_sched_process_fork must drop CLONE_THREAD children before it builds an event")
	}
}

func TestOnePodsLookupsCannotPushOutAnotherPodsHostnames(t *testing.T) {
	maps := bpfSource(t, "maps.h")
	if !strings.Contains(maps, "#define DNS_RESOLVED_CGROUP_BUDGET 8192") {
		t.Error("each cgroup must keep the old shared size, so no pod remembers fewer hostnames than before")
	}
	for _, name := range []string{"dns_resolved", "dns_resolved6"} {
		block, ok := mapBlock(maps, name)
		if !ok {
			t.Fatalf("map %s not found", name)
		}
		for _, want := range []string{
			"__uint(max_entries, 4 * DNS_RESOLVED_CGROUP_BUDGET);",
			"__type(value, struct dns_resolved_name);",
		} {
			if !strings.Contains(block, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
	if !strings.Contains(maps, "struct dns_resolved_name {\n\tchar name[MAX_STRING_LEN];\n\tu32 slot;") {
		t.Error("a stored hostname must remember the ring slot that owns it")
	}

	dns := bpfSource(t, "dns.c")
	next := functionBody(t, dns, "dns_name_next_slot")
	for _, want := range []string{
		".writer = DNS_NAME_WRITER_KERNEL",
		"u32 slot = *next & (DNS_RESOLVED_CGROUP_BUDGET - 1);",
		"__sync_fetch_and_add(next, 1);",
	} {
		if !strings.Contains(next, want) {
			t.Errorf("dns_name_next_slot lacks %q", want)
		}
	}
	for _, fn := range []struct{ name, store string }{
		{"dns_remember_v4", "&dns_resolved"},
		{"dns_remember_v6", "&dns_resolved6"},
	} {
		body := functionBody(t, dns, fn.name)
		recycle := strings.Index(body, "if (held && held->slot == slot)\n\t\t\t\tbpf_map_delete_elem("+fn.store+", &ok);")
		claim := strings.Index(body, "bpf_map_update_elem(&dns_name_slots, &sk, &addr, BPF_ANY);")
		if recycle < 0 || claim < 0 || recycle > claim {
			t.Errorf("%s must drop the cgroup's own oldest hostname, and only if no newer write refreshed it, before it claims the slot", fn.name)
		}
		if !strings.Contains(body, "dns_name_value(name, slot)") {
			t.Errorf("%s must stamp the stored hostname with its slot", fn.name)
		}
	}
	walk := functionBody(t, dns, "dns_walk_answers")
	for _, want := range []string{"dns_remember_v4(cgroup_id, ip, name);", "dns_remember_v6(&k6, name);"} {
		if !strings.Contains(walk, want) {
			t.Errorf("dns_walk_answers lacks %q", want)
		}
	}
	for _, fn := range []string{"dns_ingress", "dns_walk_answers"} {
		if strings.Contains(functionBody(t, dns, fn), "bpf_map_update_elem(&dns_resolved") {
			t.Errorf("%s writes a hostname around the per-cgroup ring", fn)
		}
	}
}

func TestAFullEventRingStillKeepsTheAnswersHostnames(t *testing.T) {
	ingress := functionBody(t, bpfSource(t, "dns.c"), "dns_ingress")
	walk := strings.Index(ingress, "dns_walk_answers(skb, dns_off, key.cgroup_id, q->name, &d);")
	bail := strings.Index(ingress, "if (!e) {\n\t\tdns_drop_inc();")
	if walk < 0 || bail < 0 || walk > bail {
		t.Error("dns_ingress must store the answer's hostnames before it gives up on a full event ring")
	}
	payload := strings.Index(ingress, "if (payload_on && *payload_on) {")
	emit := strings.Index(ingress, "emit_dns_payload(skb, dns_off, q, &meta);")
	if payload < 0 || emit < 0 || strings.Contains(ingress[payload:emit], "return") {
		t.Error("with full answers on, a full event ring must not stop the payload record")
	}
	if !strings.Contains(ingress[payload:emit], "int recorded = 0;") {
		t.Error("a payload record the kernel could not count must say so, so userspace counts it")
	}
	reserve := strings.Index(ingress, "struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);")
	if reserve < 0 || walk > reserve {
		t.Error("dns_ingress must walk the answers before it reserves the event, so no ring reference is held across the walk")
	}
	for name, body := range map[string]string{"payload": ingress[payload:emit], "answer": ingress[reserve:]} {
		checks := strings.Count(body, "if (pe)") + strings.Count(body, "if (!e)") + strings.Count(body, "if (e)")
		if checks != 1 {
			t.Errorf("the %s path null-checks its reserved event %d times; kernels before 6.6 treat a second check as a path that leaks the reservation", name, checks)
		}
	}
}
