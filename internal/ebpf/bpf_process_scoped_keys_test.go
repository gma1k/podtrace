package ebpf

import (
	"regexp"
	"strings"
	"testing"
)

var userspacePointerRe = regexp.MustCompile(`\b(GO_\w*GOROUTINE|GO_ARG_RECV)\(ctx\)`)

func TestUserspacePointerKeysAreProcessScoped(t *testing.T) {
	for _, file := range []string{"gotls.c", "gohandshake.c", "goacquire.c", "http3l7.c"} {
		text := bpfSource(t, file)
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#define") {
				continue
			}
			for _, loc := range userspacePointerRe.FindAllStringIndex(line, -1) {
				if strings.HasSuffix(line[:loc[0]], "process_scoped_id(") {
					continue
				}
				if trimmed == "u64 goroutine = GO_GOROUTINE(ctx);" {
					continue
				}
				t.Errorf("%s: %q uses a raw userspace pointer as a key or conn id; "+
					"another process can hold the same address", file, trimmed)
			}
		}
	}
}

func TestRawGoroutineOnlyFeedsTgidKeyedOncpu(t *testing.T) {
	text := bpfSource(t, "http3l7.c")
	useRe := regexp.MustCompile(`\bgoroutine\b`)
	for _, fn := range []string{"uprobe_h3_req_from_headers_ret", "uprobe_h3_handle_request_ret"} {
		body := functionBody(t, text, fn)
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if !useRe.MatchString(trimmed) || trimmed == "u64 goroutine = GO_GOROUTINE(ctx);" {
				continue
			}
			if strings.Contains(trimmed, "process_scoped_id(goroutine)") ||
				strings.HasPrefix(trimmed, "oncpu_") {
				continue
			}
			t.Errorf("%s: raw goroutine reaches %q", fn, trimmed)
		}
	}
}

func TestH3StashKeySeparatesClientAndServer(t *testing.T) {
	body := functionBody(t, bpfSource(t, "http3l7.c"), "h3_stash_key")
	if strings.Contains(body, "goroutine |") {
		t.Fatal("h3_stash_key ORs the client bit into a hashed key, so a key with bit 63 already set " +
			"makes a goroutine's client and server stashes collide")
	}
}

func TestRustlsConnKeyIsTheProcessScopedSocket(t *testing.T) {
	body := functionBody(t, bpfSource(t, "rustls.c"), "rustls_conn_key")
	if !strings.Contains(body, "process_scoped_id(p->sk)") {
		t.Fatal("rustls_conn_key must name the kernel socket the bytes moved on, scoped to the process " +
			"so it never collides with the plaintext path's raw socket keys")
	}
}

func TestOpenSSLAndGnuTLSConnIdsAreProcessScoped(t *testing.T) {
	text := bpfSource(t, "http.c")
	write := functionBody(t, text, "ssl_write_dispatch")
	if !strings.Contains(write, "ssl = process_scoped_id(ssl);") {
		t.Error("ssl_write_dispatch keys http_reqs and h2 state by the raw SSL*, which forked workers share")
	}
	read := functionBody(t, text, "ssl_read_complete")
	settle := strings.Index(read, "ssl_hs_settle(ctx, conn);")
	scope := strings.Index(read, "conn = process_scoped_id(conn);")
	if settle < 0 || scope < 0 || scope < settle {
		t.Error("ssl_read_complete must settle the handshake with the raw SSL* and parse with the process-scoped id")
	}
	for _, fn := range []string{"uretprobe_gnutls_record_send", "uretprobe_gnutls_record_recv"} {
		if !strings.Contains(functionBody(t, text, fn), "process_scoped_id(st->conn)") {
			t.Errorf("%s uses the raw gnutls session pointer as the conn id", fn)
		}
	}
	if !strings.Contains(functionBody(t, text, "kprobe_http_tcp_recvmsg"), "oncpu_alias_socket(st.conn, process_scoped_id(tls->conn))") {
		t.Error("kprobe_http_tcp_recvmsg aliases the socket to the raw SSL*, not the id the TLS probes use")
	}
}

func TestKafkaTopicHandlesAreProcessScoped(t *testing.T) {
	text := bpfSource(t, "kafka.c")
	re := regexp.MustCompile(`bpf_map_(lookup|update)_elem\(&kafka_topic_names, &(\w+)`)
	uses := re.FindAllStringSubmatch(text, -1)
	if len(uses) == 0 {
		t.Fatal("kafka.c no longer uses kafka_topic_names")
	}
	for _, m := range uses {
		if m[2] != "topic_id" {
			t.Errorf("kafka_topic_names is keyed by the raw rd_kafka_topic_t* %q; another process can hold the same address", m[2])
		}
	}
	if strings.Count(text, "process_scoped_id(") < len(uses) {
		t.Error("every kafka_topic_names key must come from process_scoped_id")
	}
}

func TestGRPCGoPairsAreKeyedByConnection(t *testing.T) {
	text := bpfSource(t, "grpcgo.c")
	build := functionBody(t, text, "grpc_pair_key_build")
	if strings.Contains(build, "lookup_tcp_peer") {
		t.Fatal("grpc_pair_key_build keys pairs by the OS thread's last 4-tuple, which belongs to another connection under Go's M:N scheduler")
	}
	conn := functionBody(t, text, "grpc_go_conn")
	for _, want := range []string{"bpf_map_lookup_elem(&grpc_go_offsets, &tgid)", "process_scoped_id(framer)"} {
		if !strings.Contains(conn, want) {
			t.Errorf("grpc_go_conn lacks %q", want)
		}
	}
	if !strings.Contains(functionBody(t, text, "grpc_go_conn_from_tuple"), "process_scoped_id(h)") {
		t.Error("the tuple fallback must be process scoped so loopback tuples in two pods do not collide")
	}
	for fn, kind := range map[string]string{
		"uprobe_grpc_go_write_header":   "GRPC_GO_RECV_LOOPY",
		"uprobe_grpc_go_server_headers": "GRPC_GO_RECV_SERVER",
		"uprobe_grpc_go_client_headers": "GRPC_GO_RECV_CLIENT",
	} {
		if !strings.Contains(functionBody(t, text, fn), "grpc_go_conn(GRPC_GO_RECV(ctx), "+kind+")") {
			t.Errorf("%s does not derive its conn from its receiver's framer", fn)
		}
	}
}
