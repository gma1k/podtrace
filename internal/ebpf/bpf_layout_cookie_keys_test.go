package ebpf

import (
	"strings"
	"testing"
)

func TestGoStructLayoutsAreLookedUpByTheAttachCookie(t *testing.T) {
	for _, tc := range []struct{ file, function, lookup string }{
		{"http3l7.c", "h3_field_offs", "bpf_map_lookup_elem(&h3_offsets, &cookie)"},
		{"http3l7.c", "h3_peer_path_lookup", "bpf_map_lookup_elem(&h3_peer_paths_map, &cookie)"},
		{"grpcgo.c", "grpc_go_conn", "bpf_map_lookup_elem(&grpc_go_offsets, &cookie)"},
		{"goacquire.c", "emit_pool_stats", "bpf_map_lookup_elem(&pool_offsets, &cookie)"},
	} {
		body := functionBody(t, bpfSource(t, tc.file), tc.function)
		if !strings.Contains(body, "u64 cookie = bpf_get_attach_cookie(ctx);") || !strings.Contains(body, tc.lookup) {
			t.Errorf("%s does not look its layout up by the attach cookie: want %q", tc.function, tc.lookup)
		}
	}
}

func TestGoStructLayoutMapsAreKeyedByCookieAndNeverEvicted(t *testing.T) {
	maps := bpfSource(t, "maps.h")
	for _, name := range []string{"h3_offsets", "h3_peer_paths_map", "grpc_go_offsets", "pool_offsets"} {
		block, ok := mapBlock(maps, name)
		if !ok {
			t.Fatalf("map %s not found", name)
		}
		if !strings.Contains(block, "BPF_MAP_TYPE_HASH") || strings.Contains(block, "LRU") {
			t.Errorf("%s must be a plain hash: an evicted layout makes its probes read the wrong offsets", name)
		}
		if !strings.Contains(block, "__type(key, u64);") {
			t.Errorf("%s must be keyed by the u64 attach cookie", name)
		}
	}
}
