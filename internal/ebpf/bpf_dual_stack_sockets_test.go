package ebpf

import (
	"os/exec"
	"strings"
	"testing"
)

func TestTheNestedV4ConnectOfADualStackSocketIsNotReportedTwice(t *testing.T) {
	body := functionBody(t, bpfSource(t, "network.c"), "kprobe_tcp_connect")
	skip := strings.Index(body, "BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET6)\n\t\treturn 0;")
	record := strings.Index(body, "record_start_time(&key);")
	if skip < 0 || record < 0 || skip > record {
		t.Error("kprobe_tcp_connect must return before recording when tcp_v6_connect called it for a v4-mapped peer, " +
			"or one connect(2) becomes two EVENT_CONNECT records")
	}
	if strings.Index(body, "cgroup_allows(bpf_get_current_cgroup_id())") > skip {
		t.Error("the cgroup gate must stay the first check")
	}
}

func TestAV4MappedConnectIsReportedAsItsIPv4Peer(t *testing.T) {
	body := functionBody(t, bpfSource(t, "network.c"), "kretprobe_tcp_v6_connect")
	mapped := strings.Index(body, "if (ipv6_is_v4_mapped(ca->addr6)) {")
	if mapped < 0 {
		t.Fatal("kretprobe_tcp_v6_connect must recognise a v4-mapped peer")
	}
	branch, ok := braceBody(body, mapped)
	if !ok {
		t.Fatal("unbalanced v4-mapped branch")
	}
	for _, want := range []string{
		"__builtin_memcpy(&addr_be, &ca->addr6[12], sizeof(addr_be));",
		"format_ip_port(__builtin_bswap32(addr_be), port, e->target);",
		"struct dns_resolved_key rk = { .cgroup_id = bpf_get_current_cgroup_id(), .ip = addr_be };",
		"bpf_map_lookup_elem(&dns_resolved, &rk);",
	} {
		if !strings.Contains(branch, want) {
			t.Errorf("v4-mapped branch lacks %q; the target and hostname must match a plain IPv4 connect", want)
		}
	}
	if !strings.Contains(body, "bpf_map_lookup_elem(&dns_resolved6, &k6);") {
		t.Error("a real IPv6 peer must still be resolved through dns_resolved6")
	}
}

const v4MappedHarness = `#include <stdio.h>
typedef unsigned char u8;

static int ipv6_is_v4_mapped(const u8 *a)
BODY

static int nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	return c - 'a' + 10;
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		u8 addr[16];
		for (int j = 0; j < 16; j++)
			addr[j] = (u8)(nibble(argv[i][2 * j]) << 4 | nibble(argv[i][2 * j + 1]));
		putchar(ipv6_is_v4_mapped(addr) ? '1' : '0');
	}
	putchar('\n');
	return 0;
}
`

func TestV4MappedAddressesAreRecognisedExactly(t *testing.T) {
	body := functionBody(t, bpfSource(t, "helpers.h"), "ipv6_is_v4_mapped")
	bin := buildNativeHarness(t, strings.Replace(v4MappedHarness, "BODY", body, 1))
	cases := []struct {
		name string
		addr string
		want byte
	}{
		{"v4-mapped loopback", "00000000000000000000ffff7f000001", '1'},
		{"v4-mapped any", "00000000000000000000ffff00000000", '1'},
		{"ipv6 loopback", "00000000000000000000000000000001", '0'},
		{"v4-compatible", "0000000000000000000000000a000001", '0'},
		{"nat64 prefix", "0064ff9b000000000000ffff0a000001", '0'},
		{"half marker", "00000000000000000000ff000a000001", '0'},
		{"global unicast", "20010db8000000000000ffff0a000001", '0'},
	}
	var args []string
	for _, c := range cases {
		args = append(args, c.addr)
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		if out[i] != c.want {
			t.Errorf("%s (%s): got %c, want %c", c.name, c.addr, out[i], c.want)
		}
	}
}

func TestUDPOverIPv6SocketsHasItsOwnProbes(t *testing.T) {
	text := bpfSource(t, "network.c")
	for _, probe := range []struct{ section, function, calls string }{
		{`SEC("kprobe/udpv6_sendmsg")`, "kprobe_udpv6_sendmsg", "udp_send_enter(ctx, PAIR_UDPV6_SENDMSG)"},
		{`SEC("kretprobe/udpv6_sendmsg")`, "kretprobe_udpv6_sendmsg", "udp_sendmsg_return(ctx, rc, PAIR_UDPV6_SENDMSG)"},
		{`SEC("fexit/udpv6_sendmsg")`, "fexit_udpv6_sendmsg", "udp_sendmsg_return(ctx, (long)rc, PAIR_UDPV6_SENDMSG)"},
		{`SEC("kprobe/udpv6_recvmsg")`, "kprobe_udpv6_recvmsg", "udp_recv_enter(ctx)"},
		{`SEC("kretprobe/udpv6_recvmsg")`, "kretprobe_udpv6_recvmsg", "udp_recvmsg_return(ctx, rc)"},
		{`SEC("fexit/udpv6_recvmsg")`, "fexit_udpv6_recvmsg", "udp_recvmsg_return(ctx, (long)rc)"},
	} {
		if !strings.Contains(text, probe.section+"\nint "+probe.function+"(") {
			t.Errorf("%s is not declared as %s", probe.function, probe.section)
			continue
		}
		if !strings.Contains(functionBody(t, text, probe.function), probe.calls) {
			t.Errorf("%s must share the IPv4 path through %s", probe.function, probe.calls)
		}
	}
}

func TestAV4MappedUDPSendIsCountedOnceByTheOuterProbe(t *testing.T) {
	text := bpfSource(t, "network.c")
	nested := functionBody(t, text, "udp_send_nested_in_udpv6")
	for _, want := range []string{
		"BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET6",
		"struct pair_key outer = make_pair_key(PAIR_UDPV6_SENDMSG);",
		"return bpf_map_lookup_elem(&start_times, &outer) != NULL;",
	} {
		if !strings.Contains(nested, want) {
			t.Errorf("udp_send_nested_in_udpv6 lacks %q", want)
		}
	}
	body := functionBody(t, text, "kprobe_udp_sendmsg")
	skip := strings.Index(body, "if (udp_send_nested_in_udpv6(ctx))\n\t\treturn 0;")
	enter := strings.Index(body, "udp_send_enter(ctx, PAIR_UDP_SENDMSG)")
	if skip < 0 || enter < 0 || skip > enter {
		t.Error("udp_sendmsg must skip the call udpv6_sendmsg makes for a v4-mapped peer, and only that call")
	}
}

func TestUDPv6SendsKeepTheirOwnPeer(t *testing.T) {
	maps := bpfSource(t, "maps.h")
	enum := maps[strings.Index(maps, "enum probe_pair {"):]
	enum = enum[:strings.Index(enum, "};")]
	if !strings.HasSuffix(strings.TrimSpace(enum), "PAIR_FS_SYSCALL,\n\tPAIR_UDPV6_SENDMSG,") {
		t.Error("PAIR_UDPV6_SENDMSG must be appended so the existing pair ids keep their values")
	}
	lookup := functionBody(t, bpfSource(t, "helpers.h"), "lookup_tcp_peer")
	if !strings.Contains(lookup, "prefer_pair == PAIR_UDPV6_SENDMSG") {
		t.Error("a UDPv6 send must not borrow the peer of a TCP call")
	}
	send := functionBody(t, bpfSource(t, "network.c"), "udp_sendmsg_return")
	if !strings.Contains(send, "fill_event_peer_exact(e, pair);") || !strings.Contains(send, "make_pair_key(pair)") {
		t.Error("udp_sendmsg_return must read the start time and the peer of the probe that called it")
	}
}

func TestAPeerIsNeverInheritedFromAnEarlierCall(t *testing.T) {
	text := bpfSource(t, "network.c")
	stash := functionBody(t, text, "stash_tcp_peer")
	if strings.Count(stash, "goto forget;") != 4 {
		t.Errorf("every early exit of stash_tcp_peer must forget the stashed peer, found %d", strings.Count(stash, "goto forget;"))
	}
	if strings.Contains(stash, "\t\treturn;\n") {
		t.Error("stash_tcp_peer returns without forgetting the previous call's peer")
	}
	if !strings.Contains(stash, "forget:\n\tforget_stashed_peer(&key);") {
		t.Error("stash_tcp_peer must drop the previous call's peer and target")
	}
	forget := functionBody(t, text, "forget_stashed_peer")
	for _, m := range []string{"&tcp_target", "&tcp_peer_stash"} {
		if !strings.Contains(forget, "bpf_map_delete_elem("+m+", key);") {
			t.Errorf("forget_stashed_peer does not delete %s", m)
		}
	}
	if !strings.Contains(functionBody(t, text, "stash_udp_peer"), "if (!peer_from_msghdr(msg, &peer)) {\n\t\tbpf_map_delete_elem(&tcp_peer_stash, &key);") {
		t.Error("a UDP send without a peer must forget the previous send's peer")
	}
	if !strings.Contains(functionBody(t, text, "udp_recv_enter"), "} else {\n\t\tbpf_map_delete_elem(&tcp_peer_stash, &key);") {
		t.Error("a receive on an unconnected UDP socket must forget the previous receive's peer")
	}
	for _, fn := range []string{"tcp_sendmsg_return", "tcp_recvmsg_return", "udp_recvmsg_return"} {
		body := functionBody(t, text, fn)
		if strings.Contains(body, "fill_event_peer_pref(") || !strings.Contains(body, "fill_event_peer_exact(") {
			t.Errorf("%s must take only its own call's peer, not fall back to another call on the thread", fn)
		}
	}
}
