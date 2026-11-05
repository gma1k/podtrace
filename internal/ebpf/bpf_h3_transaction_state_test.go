package ebpf

import (
	"strings"
	"testing"
)

func TestH3ServerResponseHeadersDoNotBleedIntoTheNextRequest(t *testing.T) {
	text := bpfSource(t, "http3l7.c")
	write := functionBody(t, text, "uprobe_h3_qpack_write_field")
	if !strings.Contains(write, "h3_client_inflight_key(") || !strings.Contains(write, "if (!key)\n\t\treturn 0;") {
		t.Fatal("encoder fields on a server goroutine are response headers written after the transaction was emitted; " +
			"they must not be captured into the goroutine's pending maps")
	}
	emit := functionBody(t, text, "h3_emit_txn")
	for _, stale := range []string{"&h3_pending_tp, &goroutine", "&h3_pending_hdrs, &goroutine"} {
		if strings.Contains(emit, stale) {
			t.Errorf("h3_emit_txn reads pending fields by bare goroutine (%s); client and server share it", stale)
		}
	}
	idx := strings.Index(emit, "if (!in) {")
	if idx < 0 {
		t.Fatal("h3_emit_txn has no braced branch for a missing transaction")
	}
	branch, ok := braceBody(emit, idx)
	if !ok || !strings.Contains(branch, "bpf_map_delete_elem(&h3_pending_tp, &key);") ||
		!strings.Contains(branch, "bpf_map_delete_elem(&h3_pending_hdrs, &key);") {
		t.Fatal("ending a request with no transaction in flight must drop that side's pending fields")
	}
	parse := functionBody(t, text, "uprobe_h3_parse_headers_ret")
	if !strings.Contains(parse, ".goroutine = key ? key : h3_stash_key(g, 0),") {
		t.Fatal("decoded fields must be stored under the side whose transaction they belong to")
	}
}

func TestH3AdapterDoesNotOpenArrivalsForFinishedOrLocalStreams(t *testing.T) {
	text := bpfSource(t, "nghttp3.c")
	inbound := functionBody(t, text, "h3_adapter_first_inbound")
	if !strings.Contains(inbound, "if (h3_adapter_is_client(conn) || h3_adapter_stream_was_finished(&k, conn))") {
		t.Fatal("every inbound chunk after a stream completed opens a phantom ARRIVAL and on-CPU request")
	}
	respond := functionBody(t, text, "h3_adapter_respond")
	idx := strings.Index(respond, "if (st && st->flags == H3_ADAPTER_KIND_ARRIVAL)")
	branch, ok := braceBody(respond, idx)
	if idx < 0 || !ok {
		t.Fatal("h3_adapter_respond lost its ARRIVAL branch")
	}
	if strings.Contains(branch, "h3_adapter_stream_finished") || !strings.Contains(respond, "h3_adapter_stream_finished(&k, conn);") {
		t.Fatal("a responded stream must be tombstoned even when its arrival was never seen")
	}
	if !strings.Contains(functionBody(t, text, "uprobe_nghttp3_submit_request"), "h3_adapter_mark_client((u64)PT_REGS_PARM1(ctx));") {
		t.Error("nghttp3_submit_request must mark the conn as a client conn")
	}
	if !strings.Contains(functionBody(t, bpfSource(t, "quiche.c"), "uprobe_quiche_h3_send_request"), "h3_adapter_mark_client((u64)PT_REGS_PARM1(ctx));") {
		t.Error("quiche_h3_send_request must mark the conn as a client conn")
	}
	for _, fn := range []string{"h3_adapter_is_client", "h3_adapter_stream_was_finished"} {
		if !strings.Contains(functionBody(t, text, fn), "h3_adapter_epoch(conn)") {
			t.Errorf("%s must ignore marks left on a freed conn pointer (epoch check)", fn)
		}
	}
}
