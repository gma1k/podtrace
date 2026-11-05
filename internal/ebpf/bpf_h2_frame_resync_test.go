package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const h2PlausibleHarness = `#include <stdio.h>
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
		unsigned char fh[HTTP2_FRAME_HDR];
		for (int j = 0; j < HTTP2_FRAME_HDR; j++)
			fh[j] = (unsigned char)(nibble(argv[i][2 * j]) << 4 | nibble(argv[i][2 * j + 1]));
		putchar(h2_frame_header_plausible(fh) ? '1' : '0');
	}
	putchar('\n');
	return 0;
}
`

func buildNativeHarness(t *testing.T, source string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler available")
		}
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "harness.c")
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "harness")
	if out, err := exec.Command(cc, "-std=c11", "-Wall", "-Werror", "-I", locateBPFDir(t), "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("compile h2_frame.h natively: %v\n%s", err, out)
	}
	return bin
}

func TestH2MidStreamHeaderCheckAcceptsNegotiatedSizesAndExtensions(t *testing.T) {
	bin := buildNativeHarness(t, h2PlausibleHarness)
	cases := []struct {
		name  string
		frame string
		want  bool
	}{
		{"data larger than the default max frame", "100000000000000001", true},
		{"headers padded priority end stream", "000020012d00000003", true},
		{"continuation", "001000090400000003", true},
		{"window update", "000004080000000000", true},
		{"small extension frame", "0000000a0000000000", true},
		{"priority update extension", "000010100000000000", true},
		{"large extension frame", "0400000b0000000000", false},
		{"data reserved bit", "000004000080000001", false},
		{"data unknown flag", "000010000200000001", false},
		{"data on stream zero", "000010000000000000", false},
		{"window update bad length", "000005080000000000", false},
		{"ping on a stream", "000008060000000001", false},
		{"settings on a stream", "000006040000000001", false},
		{"mysql server greeting", "4a0000000a382e302e", false},
	}
	args := make([]string, len(cases))
	for i, tc := range cases {
		args[i] = tc.frame
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("run harness: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if len(got) != len(cases) {
		t.Fatalf("harness returned %d results for %d cases: %q", len(got), len(cases), got)
	}
	for i, tc := range cases {
		if (got[i] == '1') != tc.want {
			t.Errorf("%s (%s): h2_frame_header_plausible = %c, want %v", tc.name, tc.frame, got[i], tc.want)
		}
	}
}

func TestH2WalkerValidatesEveryFrameHeader(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_frames_cb")
	idx := strings.Index(body, "if (!h2_frame_header_plausible(fh))")
	if idx < 0 {
		t.Fatal("h2_frames_cb adopts frame headers without validating them, so a desynced walk reads garbage lengths")
	}
	branch, ok := braceBody(body, idx)
	if !ok || !strings.Contains(branch, "s->off = c->avail + 1;") {
		t.Fatal("an implausible frame header must stop the walk past the buffer end so the direction is desynced")
	}
	if strings.Contains(body, "h2_mark_desync(") {
		t.Fatal("the bpf_loop callback must only signal a desync; marking it there multiplies the verifier's work")
	}
}

func TestH2WalkerDesyncsWhenTheStepBudgetRunsOut(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_walk_frames")
	loop := strings.Index(body, "bpf_loop(H2_MAX_FRAME_STEPS")
	if loop < 0 {
		t.Fatal("h2_walk_frames no longer walks frames with bpf_loop")
	}
	after := body[loop:]
	if !strings.Contains(after, "if (s->off != c.avail)") || !strings.Contains(after, "h2_desync(conn, dir)") {
		t.Fatal("a walk that stopped short of, or was signalled past, the buffer end must desync the direction; " +
			"otherwise the next buffer is parsed from a non-boundary offset")
	}
}

func TestH2FrameWalkIsVerifiedOncePerProgram(t *testing.T) {
	text := bpfSource(t, "h2.c")
	if !strings.Contains(text, "__noinline int h2_walk_frames(u64 base_addr, u64 avail, u64 conn, u32 dir, u32 transport)") {
		t.Fatal("the frame walk must be a global function; inlined once per iovec segment it exceeds the verifier's instruction limit")
	}
	if !strings.Contains(functionBody(t, text, "h2_emit_frames"), "h2_walk_frames((u64)base, avail, conn, dir, transport);") {
		t.Fatal("h2_emit_frames must delegate to the global frame walk")
	}
}

func TestH2PartialFrameHeaderIsCopiedWithOneBoundedRead(t *testing.T) {
	text := bpfSource(t, "h2.c")
	keep := functionBody(t, text, "h2_keep_partial")
	if !strings.Contains(keep, "bpf_probe_read_user(&fs->hdr_partial[have & 15], n, src);") {
		t.Fatal("the partial header must be read with one masked, bounded copy")
	}
	if !strings.Contains(bpfSource(t, "maps.h"), "u8  hdr_partial[24];") {
		t.Fatal("hdr_partial must hold the masked offset plus a full frame header")
	}
	if strings.Count(functionBody(t, text, "h2_frames_cb"), "h2_keep_partial(") != 3 {
		t.Fatal("every partial-header path must use h2_keep_partial instead of per-byte branches")
	}
}

func TestH2DesyncedDirectionResumesOnlyAtAFrameBoundary(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_walk_frames")
	idx := strings.Index(body, "else if (fs->desync)")
	if idx < 0 {
		t.Fatal("h2_walk_frames ignores the desync flag")
	}
	branch, ok := braceBody(body, idx)
	if !ok || !strings.Contains(branch, "if (!h2_start_looks_h2(base, avail))") ||
		!strings.Contains(branch, "return 0;") {
		t.Fatal("a desynced direction must skip buffers until one starts with a strictly valid frame header")
	}
}

func TestH2DesyncConsumesSequenceOnce(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_mark_desync")
	idx := strings.Index(body, "if (!fs->desync)")
	if idx < 0 || !strings.Contains(body[idx:], "h2_next_seq(conn, dir)") {
		t.Fatal("entering desync must consume one seq so userspace skips the gap and resets its HPACK window")
	}
	if !strings.Contains(bpfSource(t, "maps.h"), "u8  desync;") {
		t.Fatal("struct h2_frame_state lacks the desync flag")
	}
}

func TestH2DroppedSegmentsDesyncInsteadOfRestarting(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_emit_message")
	if strings.Contains(body, "bpf_map_delete_elem(&h2_frame_state") {
		t.Fatal("deleting the frame state makes the next buffer parse from offset 0 as if it were a frame boundary")
	}
	if !strings.Contains(body, "h2_desync(conn, dir)") {
		t.Fatal("segments beyond H2_MAX_SEGS must desync the direction")
	}
}

func TestH2FrameHeaderSplitAcrossThreeBuffersIsKept(t *testing.T) {
	body := functionBody(t, bpfSource(t, "h2.c"), "h2_frames_cb")
	if !strings.Contains(body, "fs->hdr_have = (u8)(have + avail_here);") {
		t.Fatal("a frame header still incomplete after a second buffer must keep accumulating, not be dropped")
	}
}

func TestTLSCloseForgetsHTTP2State(t *testing.T) {
	text := bpfSource(t, "network.c")
	if !strings.Contains(functionBody(t, text, "uprobe_SSL_free"), "ssl_forget_l7(") {
		t.Fatal("SSL_free must drop the session's HTTP state; TLS connections never reach tcp_close's h2 cleanup")
	}
	forget := functionBody(t, text, "ssl_forget_l7")
	for _, want := range []string{"process_scoped_id(ssl)", "bpf_map_delete_elem(&http_reqs, &conn)", "h2_forget_conn(conn)"} {
		if !strings.Contains(forget, want) {
			t.Errorf("ssl_forget_l7 lacks %q", want)
		}
	}
}
