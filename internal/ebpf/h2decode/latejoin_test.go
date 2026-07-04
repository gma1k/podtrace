package h2decode

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// literalInsert hand-crafts a "literal with incremental indexing, literal
// name" representation (RFC 7541 §6.2.1) for short ASCII strings.
func literalInsert(name, value string) []byte {
	block := []byte{0x40, byte(len(name))}
	block = append(block, name...)
	block = append(block, byte(len(value)))
	block = append(block, value...)
	return block
}

func fieldNames(fields []hpack.HeaderField) []string {
	var names []string
	for _, f := range fields {
		names = append(names, f.Name+"="+f.Value)
	}
	return names
}

func TestReadInteger(t *testing.T) {
	cases := []struct {
		name     string
		buf      []byte
		prefix   uint8
		value    int
		consumed int
		err      error
	}{
		{"single byte", []byte{0x0a}, 5, 10, 1, nil},
		{"prefix boundary continues", []byte{0x1f, 0x00}, 5, 31, 2, nil},
		{"multi byte", []byte{0x1f, 0x9a, 0x0a}, 5, 1337, 3, nil},
		{"empty", nil, 7, 0, 0, errHPACKTruncated},
		{"missing continuation", []byte{0xff}, 7, 0, 0, errHPACKTruncated},
		{"overflow", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, 7, 0, 0, errHPACKIntegerOverflow},
	}
	for _, tc := range cases {
		value, consumed, err := readInteger(tc.buf, tc.prefix)
		if !errors.Is(err, tc.err) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.err)
		}
		if err == nil && (value != tc.value || consumed != tc.consumed) {
			t.Fatalf("%s: got (%d, %d), want (%d, %d)", tc.name, value, consumed, tc.value, tc.consumed)
		}
	}
}

func TestStaticTableIndexedFields(t *testing.T) {
	d := &lateJoinDecoder{}
	fields, complete, err := d.decodeBlock([]byte{0x82, 0x87, 0x88})
	if err != nil || !complete {
		t.Fatalf("static-only block: complete=%v err=%v", complete, err)
	}
	want := []string{":method=GET", ":scheme=https", ":status=200"}
	got := fieldNames(fields)
	if len(got) != len(want) {
		t.Fatalf("fields = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestStaticTableMatchesRFC(t *testing.T) {
	checks := map[int]hpack.HeaderField{
		1:  {Name: ":authority"},
		4:  {Name: ":path", Value: "/"},
		8:  {Name: ":status", Value: "200"},
		14: {Name: ":status", Value: "500"},
		15: {Name: "accept-charset"},
		31: {Name: "content-type"},
		61: {Name: "www-authenticate"},
	}
	for index, want := range checks {
		got := hpackStaticTable[index-1]
		if got != want {
			t.Fatalf("static[%d] = %v, want %v", index, got, want)
		}
	}
}

func TestLateJoinSkipsPreAttachAndRecovers(t *testing.T) {
	enc := newBlockEncoder()
	preAttach := enc.encode(reqFields("POST", "/pkg.Svc/Old")...)
	steadyState := enc.encode(reqFields("POST", "/pkg.Svc/Old")...)
	newRoute := enc.encode(reqFields("POST", "/pkg.Svc/New")...)
	newRouteRepeat := enc.encode(reqFields("POST", "/pkg.Svc/New")...)
	_ = preAttach

	d := &lateJoinDecoder{}

	fields, complete, err := d.decodeBlock(steadyState)
	if err != nil {
		t.Fatalf("steady-state block errored: %v", err)
	}
	if complete {
		t.Fatal("steady-state block cannot be complete on a late join")
	}
	for _, f := range fields {
		if f.Name == ":path" {
			t.Fatalf("pre-attach :path must not resolve, got %q", f.Value)
		}
	}

	fields, _, err = d.decodeBlock(newRoute)
	if err != nil {
		t.Fatalf("new-route block errored: %v", err)
	}
	if !hasField(fields, ":path", "/pkg.Svc/New") {
		t.Fatalf("new-route literal :path missing: %v", fieldNames(fields))
	}

	fields, _, err = d.decodeBlock(newRouteRepeat)
	if err != nil {
		t.Fatalf("new-route repeat errored: %v", err)
	}
	if !hasField(fields, ":path", "/pkg.Svc/New") {
		t.Fatalf("indexed post-attach :path did not resolve: %v", fieldNames(fields))
	}
}

func TestPlaceholderInsertKeepsOrdinalsCorrect(t *testing.T) {
	enc := newBlockEncoder()
	_ = enc.encode(hf("x-token", "alpha"))
	nameRefInsert := enc.encode(hf("x-token", "beta"))
	fullLiteral := enc.encode(hf("x-other", "gamma"))
	bothIndexed := enc.encode(hf("x-token", "beta"), hf("x-other", "gamma"))

	d := &lateJoinDecoder{}

	fields, complete, err := d.decodeBlock(nameRefInsert)
	if err != nil || complete || len(fields) != 0 {
		t.Fatalf("name-ref insert: fields=%v complete=%v err=%v", fieldNames(fields), complete, err)
	}

	fields, complete, err = d.decodeBlock(fullLiteral)
	if err != nil || !complete || !hasField(fields, "x-other", "gamma") {
		t.Fatalf("full literal: fields=%v complete=%v err=%v", fieldNames(fields), complete, err)
	}

	fields, complete, err = d.decodeBlock(bothIndexed)
	if err != nil {
		t.Fatalf("indexed pair errored: %v", err)
	}
	if complete {
		t.Fatal("placeholder-backed reference must mark the block partial")
	}
	if len(fields) != 1 || !hasField(fields, "x-other", "gamma") {
		t.Fatalf("expected exactly x-other=gamma, got %v", fieldNames(fields))
	}
}

func TestSensitiveNeverIndexedField(t *testing.T) {
	enc := newBlockEncoder()
	block := enc.encode(hpack.HeaderField{Name: "authorization", Value: "secret", Sensitive: true})
	d := &lateJoinDecoder{}
	fields, complete, err := d.decodeBlock(block)
	if err != nil || !complete || !hasField(fields, "authorization", "secret") {
		t.Fatalf("never-indexed field: fields=%v complete=%v err=%v", fieldNames(fields), complete, err)
	}
}

func TestDynamicTableSizeUpdateParsed(t *testing.T) {
	enc := newBlockEncoder()
	enc.enc.SetMaxDynamicTableSize(256)
	block := enc.encode(reqFields("GET", "/sized")...)
	d := &lateJoinDecoder{}
	fields, complete, err := d.decodeBlock(block)
	if err != nil || !complete || !hasField(fields, ":path", "/sized") {
		t.Fatalf("size-update block: fields=%v complete=%v err=%v", fieldNames(fields), complete, err)
	}
}

func TestMalformedBlocks(t *testing.T) {
	cases := []struct {
		name  string
		block []byte
		err   error
	}{
		{"zero index", []byte{0x80}, errHPACKZeroIndex},
		{"index out of range", []byte{0xff, 0xff, 0xff, 0x0f}, errHPACKIndexRange},
		{"truncated integer", []byte{0xff}, errHPACKTruncated},
		{"truncated string", []byte{0x00, 0x05, 'a'}, errHPACKTruncated},
	}
	for _, tc := range cases {
		d := &lateJoinDecoder{}
		_, _, err := d.decodeBlock(tc.block)
		if !errors.Is(err, tc.err) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.err)
		}
	}
}

func TestResetEpochDiscardsWindow(t *testing.T) {
	enc := newBlockEncoder()
	first := enc.encode(hf("x-route", "/a"))
	repeat := enc.encode(hf("x-route", "/a"))

	d := &lateJoinDecoder{}
	if _, complete, err := d.decodeBlock(first); err != nil || !complete {
		t.Fatalf("literal insert failed: complete=%v err=%v", complete, err)
	}
	d.resetEpoch()
	fields, complete, err := d.decodeBlock(repeat)
	if err != nil {
		t.Fatalf("post-reset block errored: %v", err)
	}
	if complete || len(fields) != 0 {
		t.Fatalf("post-reset reference resolved from a discarded window: %v", fieldNames(fields))
	}
}

func TestInsertWindowBounded(t *testing.T) {
	d := &lateJoinDecoder{}
	for i := 0; i < maxTrackedInserts+50; i++ {
		block := literalInsert("x-k", fmt.Sprintf("v%d", i))
		if _, _, err := d.decodeBlock(block); err != nil {
			t.Fatalf("insert %d errored: %v", i, err)
		}
	}
	if len(d.inserts) > maxTrackedInserts {
		t.Fatalf("window grew to %d, cap is %d", len(d.inserts), maxTrackedInserts)
	}
	// The newest insertion must still resolve at dynamic index 62.
	fields, complete, err := d.decodeBlock([]byte{0x80 | 62})
	if err != nil || !complete || !hasField(fields, "x-k", fmt.Sprintf("v%d", maxTrackedInserts+49)) {
		t.Fatalf("newest entry lost after compaction: fields=%v complete=%v err=%v",
			fieldNames(fields), complete, err)
	}
}

func TestDifferentialAgainstReferenceDecoder(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	names := []string{":authority", "x-request-id", "content-type", "grpc-timeout",
		"user-agent", "x-b3-traceid", "cookie", "x-very-long-header-name-for-huffman"}
	values := []string{"demo.svc:443", "application/grpc", "10S", "podtrace-test/1.0",
		"aa", "session=0123456789abcdef0123456789abcdef", "text/plain; charset=utf-8"}
	paths := []string{"/pkg.Svc/Do", "/pkg.Svc/Other", "/api/v1/orders", "/healthz"}

	enc := newBlockEncoder()
	lateJoin := &lateJoinDecoder{}
	reference := hpack.NewDecoder(4096, nil)

	for i := 0; i < 300; i++ {
		fields := reqFields("POST", paths[rng.Intn(len(paths))])
		for n := rng.Intn(4); n > 0; n-- {
			fields = append(fields, hpack.HeaderField{
				Name:      names[rng.Intn(len(names))],
				Value:     values[rng.Intn(len(values))],
				Sensitive: rng.Intn(8) == 0,
			})
		}
		block := enc.encode(fields...)

		got, complete, err := lateJoin.decodeBlock(block)
		if err != nil {
			t.Fatalf("block %d: late-join errored: %v", i, err)
		}
		if !complete {
			t.Fatalf("block %d: fully-observed stream decoded partial", i)
		}
		want, err := reference.DecodeFull(block)
		if err != nil {
			t.Fatalf("block %d: reference decoder errored: %v", i, err)
		}
		if len(got) != len(want) {
			t.Fatalf("block %d: %d fields, reference has %d", i, len(got), len(want))
		}
		for j := range want {
			if got[j].Name != want[j].Name || got[j].Value != want[j].Value {
				t.Fatalf("block %d field %d: got %s=%s, want %s=%s",
					i, j, got[j].Name, got[j].Value, want[j].Name, want[j].Value)
			}
		}
	}
}

func hasField(fields []hpack.HeaderField, name, value string) bool {
	for _, f := range fields {
		if f.Name == name && f.Value == value {
			return true
		}
	}
	return false
}
