package ebpf

import (
	"strings"
	"testing"
)

func TestRustlsWritesAreParsedWithTheAcceptedCount(t *testing.T) {
	text := bpfSource(t, "rustls.c")
	if strings.Contains(functionBody(t, text, "uprobe_rustls_write"), "RUSTLS_LEN(ctx)") {
		t.Fatal("uprobe_rustls_write parses the requested length; rustls may accept fewer bytes and the caller retries the rest")
	}
	ret := functionBody(t, text, "uretprobe_rustls_write")
	for _, want := range []string{"RUSTLS_RET_OK(ctx)", "RUSTLS_RET_COUNT(ctx)", "st->len = count;"} {
		if !strings.Contains(ret, want) {
			t.Errorf("uretprobe_rustls_write lacks %q", want)
		}
	}
}

func TestRustlsWritesAreKeyedByTheSocketTheyAreSentOn(t *testing.T) {
	text := bpfSource(t, "rustls.c")
	if !strings.Contains(text, "SEC(\"kprobe/tcp_sendmsg\")\nint kprobe_rustls_tcp_sendmsg(struct pt_regs *ctx)") {
		t.Fatal("a pending rustls write must be parsed at the thread's next tcp_sendmsg, which names its socket")
	}
	if !strings.Contains(functionBody(t, text, "kprobe_rustls_tcp_sendmsg"), "rustls_dispatch_write(ctx, rustls_thread_key(), process_scoped_id(sk));") {
		t.Fatal("kprobe_rustls_tcp_sendmsg must key the write by the process-scoped socket it is sent on")
	}
	if strings.Contains(functionBody(t, bpfSource(t, "http.c"), "kprobe_http_tcp_sendmsg"), "rustls") {
		t.Fatal("the rustls parse must stay out of kprobe_http_tcp_sendmsg; together they exceed the verifier's instruction limit")
	}
	dispatch := functionBody(t, text, "rustls_dispatch_write")
	if !strings.Contains(dispatch, "RUSTLS_WRITE_STALE_NS") {
		t.Error("a pending write whose socket send never came must expire rather than attach to a later send")
	}
	if !strings.Contains(functionBody(t, text, "uprobe_rustls_write"), "rustls_dispatch_write(ctx, key, rustls_conn_key(H2_DIR_EGRESS));") {
		t.Error("a write still pending when the next one starts must be parsed, not overwritten")
	}
}

func TestTCPPeerStashCarriesTheSocket(t *testing.T) {
	if !strings.Contains(bpfSource(t, "maps.h"), "u64 sk;\n};\nstruct {\n\t__uint(type, BPF_MAP_TYPE_LRU_HASH);\n\t__uint(max_entries, 4096);\n\t__type(key, struct pair_key);\n\t__type(value, struct tcp_peer);") {
		t.Fatal("struct tcp_peer must carry the socket pointer")
	}
	if !strings.Contains(functionBody(t, bpfSource(t, "network.c"), "stash_tcp_peer"), "peer.sk = (u64)sk;") {
		t.Fatal("stash_tcp_peer must record the socket pointer")
	}
}

func TestTCPCloseForgetsSocketKeyedTLSHTTP2State(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "kprobe_h2_tcp_close")
	if !strings.Contains(body, "u64 scoped = process_scoped_id(sk);") || !strings.Contains(body, "h2_forget_conn(scoped);") {
		t.Fatal("rustls h2 state is keyed by the process-scoped socket; tcp_close must forget it too")
	}
}
