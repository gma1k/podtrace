package probes

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The HPACK Huffman decode FSM in bpf/hpack_huffman.h is generated from RFC
// 7541 Appendix B. This test guards that committed table against accidental
// corruption (e.g. a botched regeneration) by re-running the same nibble FSM
// the eBPF decoder uses against known encodings, with no external dependency.

const (
	huffFlagSym  = 1
	huffFlagEOS  = 8
	huffFlagFail = 4
)

type huffEntry struct{ next, sym, flags int }

func loadHuffTable(t *testing.T) [][16]huffEntry {
	t.Helper()
	// internal/ebpf/probes -> repo root -> bpf/hpack_huffman.h
	path := filepath.Join("..", "..", "..", "bpf", "hpack_huffman.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(`\{(\d+),(\d+),(\d+)\}`)
	m := re.FindAllStringSubmatch(string(data), -1)
	if len(m) == 0 || len(m)%16 != 0 {
		t.Fatalf("unexpected entry count %d (want nonzero multiple of 16)", len(m))
	}
	tbl := make([][16]huffEntry, len(m)/16)
	for i, g := range m {
		a, _ := strconv.Atoi(g[1])
		b, _ := strconv.Atoi(g[2])
		c, _ := strconv.Atoi(g[3])
		tbl[i/16][i%16] = huffEntry{a, b, c}
	}
	return tbl
}

// decodeHuff mirrors the per-nibble FSM walk in bpf/h2.c exactly.
func decodeHuff(tbl [][16]huffEntry, in []byte) string {
	state := 0
	out := make([]byte, 0, len(in)*2)
	for _, bv := range in {
		for _, nib := range []int{int(bv >> 4), int(bv & 0xf)} {
			e := tbl[state&0xff][nib]
			if e.flags&(huffFlagFail|huffFlagEOS) != 0 {
				return string(out)
			}
			if e.flags&huffFlagSym != 0 {
				out = append(out, byte(e.sym))
			}
			state = e.next
		}
	}
	return string(out)
}

func TestHPACKHuffmanTable_KnownEncodings(t *testing.T) {
	tbl := loadHuffTable(t)
	cases := []struct {
		enc  []byte
		want string
	}{
		{[]byte{0x60, 0xd5, 0x48, 0x5f, 0x2b, 0xce, 0x9a, 0x68}, "/index.html"},
		{[]byte{0x60, 0x75, 0x99, 0x8b, 0x50, 0x5b, 0x11}, "/api/users"},
		{[]byte{0xc5, 0x83, 0x7f}, "GET"},
		{[]byte{0xd7, 0xab, 0x76, 0xff}, "POST"},
		{[]byte{0x10, 0x01}, "200"},
		{[]byte{0x68, 0x0d, 0x7f}, "404"},
		{[]byte{0x63, 0x71, 0x6c, 0xee, 0x62, 0x15, 0x8d, 0x05, 0x4c, 0xe7, 0x93}, "/Service/Method"},
	}
	for _, c := range cases {
		if got := decodeHuff(tbl, c.enc); got != c.want {
			t.Errorf("decodeHuff(% x) = %q, want %q", c.enc, got, c.want)
		}
	}
}
