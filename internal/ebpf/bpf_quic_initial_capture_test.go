package ebpf

import (
	"strings"
	"testing"
)

func TestQUICInitialBudgetIsPerConnectionAndExpires(t *testing.T) {
	maps := bpfSource(t, "maps.h")
	key := maps[strings.Index(maps, "struct quic_flow_key {"):]
	key = key[:strings.Index(key, "};")]
	if !strings.Contains(key, "u16 lport;") {
		t.Fatal("quic_flow_key has no local port, so every connection a pod opens to one server shares one budget")
	}
	text := bpfSource(t, "http3.c")
	budget := functionBody(t, text, "quic_budget_take")
	if !strings.Contains(budget, "QUIC_INITIAL_WINDOW_NS") {
		t.Fatal("the per-flow Initial budget never resets, so a reconnect on a reused flow key is invisible")
	}
	ship := functionBody(t, text, "quic_ship")
	if !strings.Contains(ship, "k.lport = bpf_ntohs(port_be);") || !strings.Contains(ship, "rec->lport = k.lport;") {
		t.Fatal("quic_ship must key and report the local port")
	}
	egress := functionBody(t, text, "http3_egress")
	ingress := functionBody(t, text, "http3_ingress")
	if !strings.Contains(egress, "2, 0, l4, 1)") || !strings.Contains(ingress, "0, 2, l4, 0)") {
		t.Fatal("egress must take the peer port from dport and the local from sport; ingress the reverse")
	}
}

func TestQUICInitialScratchHasOneSlotPerDirection(t *testing.T) {
	block, ok := mapBlock(bpfSource(t, "maps.h"), "quic_initial_scratch")
	if !ok {
		t.Fatal("quic_initial_scratch not found")
	}
	if !strings.Contains(block, "__uint(max_entries, 2);") {
		t.Fatal("egress (process context, BH enabled) and ingress (softirq) must not share one scratch record")
	}
	ship := functionBody(t, bpfSource(t, "http3.c"), "quic_ship")
	if !strings.Contains(ship, "u32 slot = egress ? QUIC_SCRATCH_EGRESS : QUIC_SCRATCH_INGRESS;") ||
		!strings.Contains(ship, "bpf_map_lookup_elem(&quic_initial_scratch, &slot)") {
		t.Fatal("quic_ship must pick its scratch slot by direction")
	}
}
