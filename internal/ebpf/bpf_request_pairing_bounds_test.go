package ebpf

import (
	"strings"
	"testing"
)

func TestFastCGIRequestsAreEvictable(t *testing.T) {
	assertMapsAreLRU(t, []string{"fastcgi_reqs"})
}

func TestFastCGIEndRequestIsFoundPastLargeRecords(t *testing.T) {
	body := functionBody(t, bpfSource(t, "fastcgi.c"), "kprobe_unix_stream_sendmsg")
	if strings.Contains(body, "FCGI_MAX_RECORD_BODY") {
		t.Fatal("the END_REQUEST walk gives up on STDOUT records over 8 KiB, which php-fpm sends in the same write")
	}
	if !strings.Contains(body, "k < FCGI_END_SCAN_RECORDS") {
		t.Fatal("the END_REQUEST walk must use FCGI_END_SCAN_RECORDS")
	}
}

func TestPlaintextReceiveParsesOnlyTheFirstSegment(t *testing.T) {
	text := bpfSource(t, "http.c")
	if !strings.Contains(functionBody(t, text, "kprobe_http_tcp_recvmsg"), ".out_len = avail,") {
		t.Fatal("kprobe_http_tcp_recvmsg must remember how long the first receive segment is")
	}
	ret := functionBody(t, text, "http_tcp_recvmsg_return")
	if !strings.Contains(ret, "if (first_seg < n)") {
		t.Fatal("a readv/recvmsg return is parsed past the end of iov[0] into unrelated process memory")
	}
	for _, call := range []string{"http_emit_response(ctx, base, n,", "http_emit_request(ctx, base, n,"} {
		if !strings.Contains(ret, call) {
			t.Errorf("http_tcp_recvmsg_return must parse the clamped length: %q missing", call)
		}
	}
}

func TestPoolExhaustionIsOnlyHookedWhereAWaitExists(t *testing.T) {
	text := bpfSource(t, "database.c")
	for _, prog := range []string{"uprobe/PQexec_pool", "uprobe/mysql_real_query_pool"} {
		if strings.Contains(text, prog) {
			t.Errorf("%s reports the connection's age as pool exhaustion on every query", prog)
		}
	}
}
