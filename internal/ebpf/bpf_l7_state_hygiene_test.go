package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTCPCloseForgetsKnownHTTP2ConnectionsOfUntracedCgroups(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "kprobe_h2_tcp_close")
	if regexp.MustCompile(`if\s*\(!http_should_trace\(\)\)\s*return`).MatchString(body) {
		t.Fatal("tcp_close returns early for untraced cgroups; state of a cgroup that stopped being traced survives into the socket's next owner")
	}
	if !strings.Contains(body, "http_should_trace() || bpf_map_lookup_elem(&h2_conns, &sk)") {
		t.Fatal("tcp_close must forget a raw-socket HTTP/2 connection it knows even when the closing cgroup is no longer traced")
	}
}

func TestRecreatedFrameStateOfAKnownConnectionResyncs(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_walk_prepare")
	if !strings.Contains(body, "u8 was_known = known != NULL;") {
		t.Fatal("h2_walk_prepare must remember whether the connection was already known before inserting it")
	}
	recreate := regexp.MustCompile(`if \(!fs\) \{[^}]*if \(was_known\)\s*h2_join_direction\(fs, conn, dir\);`)
	if !recreate.MatchString(body) {
		t.Fatal("frame state evicted from a known connection must restart desynced; parsing mid-frame bytes as a header emits garbage HEADERS")
	}
}

func TestADirectionThatNeverEmittedJoinsWithoutAFakeGap(t *testing.T) {
	join := functionBody(t, bpfSource(t, "h2.c"), "h2_join_direction")
	lost := regexp.MustCompile(`if \(bpf_map_lookup_elem\(&h2_seq, &k\)\)\s*h2_mark_desync\(fs, conn, dir\);\s*else\s*fs->desync = 1;`)
	if !lost.MatchString(join) {
		t.Fatal("only a direction that already emitted records may consume a seq when it rejoins; the first packet of the other direction of a new connection must resync without one, or userspace holds it 2s behind a gap that lost nothing and resets its HPACK window")
	}
}

func TestPeekedTCPReceivesAreNotParsedAsConsumedData(t *testing.T) {
	protocols := bpfSource(t, "protocols.h")
	if !strings.Contains(functionBody(t, protocols, "tcp_copied_seq"), "&tp->copied_seq") {
		t.Fatal("tcp_copied_seq must read tcp_sock.copied_seq, which MSG_PEEK leaves unchanged")
	}
	if !strings.Contains(functionBody(t, protocols, "tcp_recv_was_peek"), "if (!seq_known || !tcp_copied_seq(sk, &after))\n\t\treturn 0;") {
		t.Fatal("an unreadable copied_seq must not drop the receive")
	}
	http := bpfSource(t, "http.c")
	if !strings.Contains(functionBody(t, http, "kprobe_http_tcp_recvmsg"), "st.seq_known = tcp_copied_seq(st.conn, &st.copied_seq);") {
		t.Fatal("kprobe_http_tcp_recvmsg must record copied_seq before the receive")
	}
	if !strings.Contains(functionBody(t, http, "http_tcp_recvmsg_return"), "if (tcp_recv_was_peek(sk, seq_known, copied_seq))\n\t\treturn 0;") {
		t.Fatal("http_tcp_recvmsg_return parses a MSG_PEEK receive; the same request is parsed again when it is read")
	}
	h2 := bpfSource(t, "h2.c")
	if !strings.Contains(functionBody(t, h2, "h2_stash_message"), "if (recv)\n\t\tinfo.seq_known = tcp_copied_seq(info.conn_id, &info.copied_seq);") {
		t.Fatal("h2_stash_message must record copied_seq for receives")
	}
	if !strings.Contains(functionBody(t, h2, "kprobe_h2_tcp_recvmsg"), "h2_stash_message(ctx, &h2_recv_base, 1);") {
		t.Fatal("kprobe_h2_tcp_recvmsg must stash as a receive")
	}
	if !strings.Contains(functionBody(t, h2, "h2_tcp_recvmsg_return"), "if (tcp_recv_was_peek(info.conn_id, info.seq_known, info.copied_seq))\n\t\treturn 0;") {
		t.Fatal("h2_tcp_recvmsg_return parses a MSG_PEEK receive; HPACK inserts would be applied twice")
	}
	if !strings.Contains(bpfSource(t, "vmlinux.h"), "struct tcp_sock {\n\tunsigned int copied_seq;\n};") {
		t.Fatal("the stub vmlinux.h must declare tcp_sock.copied_seq for builds without bpftool")
	}
}

func TestRedisArgvCommandIsBoundedByItsLength(t *testing.T) {
	body := functionBody(t, bpfSource(t, "redis.c"), "uprobe_redisCommandArgv")
	if !strings.Contains(body, "PT_REGS_PARM4(ctx)") {
		t.Fatal("uprobe_redisCommandArgv must read argvlen; argv entries need not be NUL-terminated")
	}
	lenRead := strings.Index(body, "bpf_probe_read_user(&len, sizeof(len), argvlen)")
	strRead := strings.Index(body, "bpf_probe_read_user_str(buf, sizeof(buf), cmd_ptr)")
	if lenRead < 0 || strRead < 0 || strRead < lenRead {
		t.Fatal("argv[0] may only be read as a C string when argvlen is absent")
	}
	if !strings.Contains(body, "bpf_probe_read_user(buf, n, cmd_ptr)") {
		t.Fatal("argv[0] must be read with exactly its argvlen length")
	}
}

func TestKafkaTopicNamesAreForgottenWhenTheLastReferenceIsDestroyed(t *testing.T) {
	text := bpfSource(t, "kafka.c")
	destroy := functionBody(t, text, "uprobe_rd_kafka_topic_destroy")
	for _, want := range []string{
		"u64 topic_id = process_scoped_id(topic_ptr);",
		"if (!refs)\n\t\treturn 0;",
		"if (*refs > 1) {",
		"bpf_map_delete_elem(&kafka_topic_names, &topic_id);",
		"bpf_map_delete_elem(&kafka_topic_refs, &topic_id);",
	} {
		if !strings.Contains(destroy, want) {
			t.Errorf("uprobe_rd_kafka_topic_destroy lacks %q", want)
		}
	}
	if !strings.Contains(functionBody(t, text, "uretprobe_rd_kafka_topic_new"), "bpf_map_update_elem(&kafka_topic_refs, &topic_id, &one, BPF_NOEXIST)") {
		t.Error("rd_kafka_topic_new must count the reference it hands out")
	}
	block, ok := mapBlock(bpfSource(t, "maps.h"), "kafka_topic_refs")
	if !ok || !strings.Contains(block, "BPF_MAP_TYPE_LRU_HASH") {
		t.Error("kafka_topic_refs must be an LRU map")
	}
	attach, err := os.ReadFile(filepath.Join(filepath.Dir(locateBPFDir(t)), "internal", "ebpf", "probes", "protocols.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(attach), `{"uprobe_rd_kafka_topic_destroy", "", "rd_kafka_topic_destroy"}`) {
		t.Error("the destroy probe is never attached")
	}
}

func TestFastCGIProbesSkipUntracedCgroupsBeforeTouchingMaps(t *testing.T) {
	text := bpfSource(t, "fastcgi.c")
	for _, fn := range []string{"kprobe_unix_stream_recvmsg", "kprobe_unix_stream_sendmsg"} {
		body := strings.TrimSpace(functionBody(t, text, fn))
		if !strings.HasPrefix(body, "{\n\tif (!cgroup_allows(bpf_get_current_cgroup_id()))\n\t\treturn 0;") &&
			!strings.HasPrefix(body, "if (!cgroup_allows(bpf_get_current_cgroup_id()))\n\t\treturn 0;") {
			t.Errorf("%s must check the cgroup first; node-wide unix socket traffic otherwise churns recvmsg_args", fn)
		}
	}
}

func TestDeferredRustlsWritesOnlyAttachToATLSRecordSend(t *testing.T) {
	text := bpfSource(t, "rustls.c")
	check := functionBody(t, text, "rustls_send_is_tls_record")
	if !strings.Contains(check, "hdr[0] >= 0x14 && hdr[0] <= 0x18 && hdr[1] == 0x03") {
		t.Fatal("rustls_send_is_tls_record must match a TLS record header")
	}
	if !strings.Contains(check, "return 1;") {
		t.Fatal("an unreadable send buffer must keep the previous behaviour and dispatch")
	}
	body := functionBody(t, text, "kprobe_rustls_tcp_sendmsg")
	gate := strings.Index(body, "rustls_send_is_tls_record((struct msghdr *)PT_REGS_PARM2(ctx))")
	dispatch := strings.Index(body, "rustls_dispatch_write(ctx, key, process_scoped_id(sk));")
	if gate < 0 || dispatch < 0 || gate > dispatch {
		t.Fatal("a pending rustls write must not attach to a plaintext send on another socket")
	}
}
