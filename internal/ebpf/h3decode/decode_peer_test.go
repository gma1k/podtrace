package h3decode

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseRecord_ClampsOversizedLengths(t *testing.T) {
	buf := make([]byte, recordSize)
	for i := methodOffset; i < recordSize; i++ {
		buf[i] = 'A'
	}
	buf[31] = 200
	binary.LittleEndian.PutUint16(buf[32:34], 1000)
	buf[34] = 200

	tx, ok := ParseRecord(buf)
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if len(tx.Method) != methodMax {
		t.Errorf("method length = %d, want clamp to %d", len(tx.Method), methodMax)
	}
	if len(tx.Path) != pathMax {
		t.Errorf("path length = %d, want clamp to %d", len(tx.Path), pathMax)
	}
	if len(tx.Traceparent) != tpMax {
		t.Errorf("traceparent length = %d, want clamp to %d", len(tx.Traceparent), tpMax)
	}
}

func TestParseRecord_UnknownPeerFamily(t *testing.T) {
	rec := buildRecordFull(1, 200, true, "GET", "/x", "", 0, 99, 443,
		[]byte{1, 2, 3, 4}, nil)
	tx, ok := ParseRecord(rec)
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if tx.PeerIP != "" || tx.PeerPort != 0 {
		t.Fatalf("unknown family should yield no peer, got %q:%d", tx.PeerIP, tx.PeerPort)
	}
}

func TestParseRecord_UnspecifiedPeerAddress(t *testing.T) {
	rec := buildRecordFull(1, 200, true, "GET", "/x", "", 0, 2, 443,
		[]byte{0, 0, 0, 0}, nil)
	tx, _ := ParseRecord(rec)
	if tx.PeerIP != "" || tx.PeerPort != 0 {
		t.Fatalf("all-zero v4 address should be dropped, got %q:%d", tx.PeerIP, tx.PeerPort)
	}
}

func TestParseRecord_NativeIPv6Peer(t *testing.T) {
	addr := make([]byte, 16)
	addr[0] = 0x20
	addr[1] = 0x01
	addr[15] = 0x01
	rec := buildRecordFull(1, 200, false, "GET", "/x", "", 0, 10, 8443, addr, nil)
	tx, _ := ParseRecord(rec)
	if tx.PeerIP != "2001::1" {
		t.Fatalf("native v6 peer = %q, want 2001::1", tx.PeerIP)
	}
	if tx.PeerPort != 8443 {
		t.Fatalf("peer port = %d, want 8443", tx.PeerPort)
	}
}

func TestParseRecord_AdapterExtensionFields(t *testing.T) {
	buf := make([]byte, adapterExtSize)
	copy(buf, buildRecord(1, 200, true, "GET", "/x"))
	binary.LittleEndian.PutUint64(buf[adapterConnOffset:], 0xdeadbeef)
	binary.LittleEndian.PutUint64(buf[adapterConnOffset+8:], 0xfeed)

	tx, ok := ParseRecord(buf)
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if tx.AdapterConn != 0xdeadbeef {
		t.Errorf("AdapterConn = %#x, want 0xdeadbeef", tx.AdapterConn)
	}
	if tx.AdapterStream != 0xfeed {
		t.Errorf("AdapterStream = %#x, want 0xfeed", tx.AdapterStream)
	}
}

func TestDecoderParseRecord_ShortRecordReturnsFalse(t *testing.T) {
	d := NewDecoder([]string{"content-type"})
	if tx, ok := d.ParseRecord(make([]byte, 10)); ok || tx != nil {
		t.Fatalf("expected (nil,false) for a short record, got (%+v,%v)", tx, ok)
	}
}

func TestDecoderParseRecord_ClampsOversizedHeaderValue(t *testing.T) {
	buf := buildRecord(1, 200, true, "GET", "/x")
	buf[hdrLenOffset] = 200
	for i := 0; i < hdrValMax; i++ {
		buf[hdrValOffset+i] = 'B'
	}
	d := NewDecoder([]string{"x-big"})
	tx, ok := d.ParseRecord(buf)
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if len(tx.Headers) != 1 {
		t.Fatalf("expected 1 header, got %d", len(tx.Headers))
	}
	if got := tx.Headers[0].Value; len(got) != hdrValMax || !bytes.Equal([]byte(got), bytes.Repeat([]byte{'B'}, hdrValMax)) {
		t.Errorf("header value length = %d, want clamp to %d", len(got), hdrValMax)
	}
}
