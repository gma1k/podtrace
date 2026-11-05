package ebpf

import (
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
)

const hpackPathHarness = `#include <stdio.h>
#include <string.h>
#include "h2_frame.h"

static int nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	return c - 'a' + 10;
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		unsigned char blk[128] = {0};
		unsigned int n = (unsigned int)strlen(argv[i]) / 2;
		if (n > sizeof(blk))
			n = sizeof(blk);
		for (unsigned int j = 0; j < n; j++)
			blk[j] = (unsigned char)(nibble(argv[i][2 * j]) << 4 | nibble(argv[i][2 * j + 1]));
		unsigned int vstart = 0, vlen = 0;
		if (hpack_literal_path(blk, sizeof(blk) - 1, 0, n, &vstart, &vlen))
			printf("%.*s\n", (int)vlen, (const char *)blk + vstart);
		else
			printf("-\n");
	}
	return 0;
}
`

func hpackHex(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		if strings.HasPrefix(p, "=") {
			b.WriteString(hex.EncodeToString([]byte(p[1:])))
			continue
		}
		b.WriteString(p)
	}
	return b.String()
}

func TestHPACKPathAcceptsOnlyLiteralNonHuffmanValues(t *testing.T) {
	bin := buildNativeHarness(t, hpackPathHarness)
	cases := []struct {
		name  string
		block string
		want  string
	}{
		{"incremental indexing after method and scheme", hpackHex("8386", "440f", "=/pkg.Svc/Method"), "/pkg.Svc/Method"},
		{"without indexing", hpackHex("0405", "=/ping"), "/ping"},
		{"never indexed", hpackHex("1405", "=/ping"), "/ping"},
		{"after a new-name literal", hpackHex("4003", "=foo", "03", "=bar", "4405", "=/ping"), "/ping"},
		{"after an authority literal", hpackHex("4109", "=localhost", "4402", "=/x"), "/x"},
		{"after a table size update", hpackHex("20", "4402", "=/x"), "/x"},
		{"huffman coded", hpackHex("8386", "448f", "=/pkg.Svc/Method"), "-"},
		{"indexed static path", hpackHex("8384"), "-"},
		{"truncated value", hpackHex("440f", "=/pk"), "-"},
		{"multi-byte table size update", hpackHex("3fe11f", "4402", "=/x"), "-"},
		{"raw slash inside another field", hpackHex("4003", "=foo", "05", "=/evil"), "-"},
	}
	args := make([]string, len(cases))
	for i, tc := range cases {
		args[i] = tc.block
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("run harness: %v", err)
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(got) != len(cases) {
		t.Fatalf("harness returned %d results for %d cases: %q", len(got), len(cases), got)
	}
	for i, tc := range cases {
		if got[i] != tc.want {
			t.Errorf("%s: hpack_literal_path = %q, want %q", tc.name, got[i], tc.want)
		}
	}
}

func TestGRPCMethodSniffParsesHPACKAndGatesOnTheTarget(t *testing.T) {
	body := functionBody(t, bpfSource(t, "grpc.c"), "kprobe_grpc_tcp_sendmsg")
	gate := strings.Index(body, "if (!cgroup_allows(bpf_get_current_cgroup_id()))")
	if gate < 0 {
		t.Fatal("kprobe_grpc_tcp_sendmsg runs for every process; untargeted writes churn the shared grpc_methods map")
	}
	if strings.Index(body, "bpf_map_update_elem(&grpc_methods") < gate {
		t.Fatal("grpc_methods is written before the target gate")
	}
	if strings.Contains(body, "buf[i] == '/'") {
		t.Fatal("kprobe_grpc_tcp_sendmsg still scans raw HPACK bytes for '/', which matches inside Huffman-coded values")
	}
	if !strings.Contains(body, "hpack_literal_path(") {
		t.Fatal("kprobe_grpc_tcp_sendmsg must locate :path through the HPACK representation")
	}
}
