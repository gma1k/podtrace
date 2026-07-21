package quicinitial

import (
	"testing"
)

func TestExtractSNIErrNoSNI(t *testing.T) {
	if _, err := ExtractSNIErr([]byte{0x00}); err == nil {
		t.Fatal("decrypt failure did not error")
	}

	hs := buildClientHello("", []string{"h3"})
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pkt := buildClientInitialV(t, dcid, hs, VersionV1)
	if _, err := ExtractSNIErr(pkt); err == nil {
		t.Fatal("ClientHello without SNI reported success")
	}

	if _, ok := ExtractSNI(pkt); ok {
		t.Fatal("ExtractSNI found an SNI that is not present")
	}
}

func TestExtractPacketsErrorPaths(t *testing.T) {
	if _, err := ExtractPackets(nil); err == nil {
		t.Fatal("empty packet list did not error")
	}
	if _, err := ExtractPackets([][]byte{{0x00}}); err == nil {
		t.Fatal("all-undecryptable packets did not error")
	}

	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	notCH := buildClientInitialV(t, dcid, []byte{0x16, 0x03, 0x03}, VersionV1)
	if _, err := ExtractPackets([][]byte{notCH}); err == nil {
		t.Fatal("non-ClientHello CRYPTO reported success")
	}

	noSNI := buildClientInitialV(t, dcid, buildClientHello("", []string{"h3"}), VersionV1)
	info, err := ExtractPackets([][]byte{noSNI})
	if err == nil {
		t.Fatal("ClientHello without SNI reported success")
	}
	if len(info.ALPN) != 1 || info.ALPN[0] != "h3" {
		t.Fatalf("ALPN lost on no-SNI result: %+v", info)
	}

	hs := buildClientHello("gap.example.org", nil)
	gapOnly := buildClientInitialChunk(t, dcid, hs, 5, len(hs)-5)
	if _, err := ExtractPackets([][]byte{gapOnly}); err == nil {
		t.Fatal("non-contiguous CRYPTO reported success")
	}

	if _, err := Extract(gapOnly); err == nil {
		t.Fatal("Extract accepted non-contiguous CRYPTO")
	}
}

func TestDecryptInitialMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":             {0x00, 0x00, 0x00},
		"not a long header":     {0x40, 0, 0, 0, 1, 0, 0},
		"dcid out of range":     {0xc0, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00},
		"scid len out of range": {0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0xaa, 0xbb},
		"token len varint":      {0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
		"length too small":      buildTinyLength(),
	}
	for name, pkt := range cases {
		if _, err := Extract(pkt); err == nil {
			t.Errorf("%s: decrypt succeeded, want error", name)
		}
	}
}

func buildTinyLength() []byte {
	pkt := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
	pkt = append(pkt, 0x08)
	pkt = append(pkt, 1, 2, 3, 4, 5, 6, 7, 8)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, 0x0a)
	pkt = append(pkt, make([]byte, 10)...)
	return pkt
}

func TestDecryptInitialAEADFailure(t *testing.T) {
	hs := buildClientHello("aead.example.org", nil)
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	pkt := buildClientInitial(t, dcid, hs)
	pkt[len(pkt)-1] ^= 0xff
	if _, err := Extract(pkt); err == nil {
		t.Fatal("corrupted ciphertext decrypted successfully")
	}
}

func TestExtractNonClientHello(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	notCH := buildClientInitial(t, dcid, []byte{0x16, 0x03, 0x03, 0x00, 0x05})
	if _, err := Extract(notCH); err == nil {
		t.Fatal("non-ClientHello handshake accepted by Extract")
	}
}

func TestDecryptInitialHeaderVarintErrors(t *testing.T) {
	base := func() []byte {
		p := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
		p = append(p, 0x08)
		p = append(p, 1, 2, 3, 4, 5, 6, 7, 8)
		p = append(p, 0x00)
		return p
	}
	bigVarint := []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00}

	tokenTooLarge := append(base(), bigVarint...)

	lengthVarintFail := append(base(), 0x00)

	lengthTooLarge := append(append(base(), 0x00), bigVarint...)

	for name, pkt := range map[string][]byte{
		"token len too large":   tokenTooLarge,
		"length varint failure": lengthVarintFail,
		"length too large":      lengthTooLarge,
	} {
		if _, err := Extract(pkt); err == nil {
			t.Errorf("%s: decrypt succeeded, want error", name)
		}
	}
}

func TestReassembleCryptoVarintEdges(t *testing.T) {

	if got := reassembleCrypto([]byte{0x06, 0x00, 0x40}); got != nil {
		t.Fatalf("truncated length varint: got %x, want nil", got)
	}

	over := []byte{0x06, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00}
	if got := reassembleCrypto(over); got != nil {
		t.Fatalf("oversized offset: got %x, want nil", got)
	}
}

func TestReassembleCryptoDirect(t *testing.T) {
	crypto := func(off int, data []byte) []byte {
		out := []byte{0x06, byte(off), byte(len(data))}
		return append(out, data...)
	}

	plain := append([]byte{0x00, 0x01}, crypto(0, []byte{0xaa, 0xbb})...)
	if got := reassembleCrypto(plain); string(got) != string([]byte{0xaa, 0xbb}) {
		t.Fatalf("padding/ping skip: got %x, want aabb", got)
	}

	stop := append(crypto(0, []byte{0x11}), 0x99)
	if got := reassembleCrypto(stop); string(got) != string([]byte{0x11}) {
		t.Fatalf("unknown-frame stop: got %x, want 11", got)
	}

	if got := reassembleCrypto(crypto(2, []byte{0x01})); got != nil {
		t.Fatalf("leading gap: got %x, want nil", got)
	}

	if got := reassembleCrypto([]byte{0x00, 0x00}); got != nil {
		t.Fatalf("no crypto: got %x, want nil", got)
	}

	if got := reassembleCrypto([]byte{0x06, 0x40}); got != nil {
		t.Fatalf("truncated offset: got %x, want nil", got)
	}

	if got := reassembleCrypto([]byte{0x06, 0x00, 0x05, 0xaa}); got != nil {
		t.Fatalf("overrunning length: got %x, want nil", got)
	}
}

func TestParseClientHelloSNIFailure(t *testing.T) {
	if _, ok := parseClientHelloSNI([]byte{0x02, 0x00, 0x00, 0x00}); ok {
		t.Fatal("non-ClientHello handshake parsed as one")
	}

	hs := buildClientHello("", []string{"h2"})
	if s, ok := parseClientHelloSNI(hs); ok {
		t.Fatalf("SNI reported where none exists: %q", s)
	}
}

func TestParseClientHelloTruncations(t *testing.T) {
	full := buildClientHello("trunc.example.org", []string{"h3"})

	for cut := 4; cut < len(full); cut++ {
		_, _, _ = parseClientHello(full[:cut])
	}
	if _, _, ok := parseClientHello(full[:3]); ok {
		t.Fatal("3-byte handshake parsed as a ClientHello")
	}
}

func TestParseALPNExtensionEdges(t *testing.T) {
	if got := parseALPNExtension([]byte{0x00}); got != nil {
		t.Fatalf("short body: got %v, want nil", got)
	}

	if got := parseALPNExtension([]byte{0x00, 0xff, 0x02, 'h', '3'}); len(got) != 1 || got[0] != "h3" {
		t.Fatalf("clamped list: got %v, want [h3]", got)
	}

	if got := parseALPNExtension([]byte{0x00, 0x01, 0x00}); got != nil {
		t.Fatalf("zero-length name: got %v, want nil", got)
	}

	if got := parseALPNExtension([]byte{0x00, 0x03, 0x05, 'a'}); got != nil {
		t.Fatalf("overrunning name: got %v, want nil", got)
	}
}

func TestParseSNIExtensionMoreEdges(t *testing.T) {

	d := []byte{0x00, 0x0a, 0x00, 0x00, 0x05, 'a'}
	if _, ok := parseSNIExtension(d); ok {
		t.Fatal("overrunning host_name accepted")
	}

	host := "sni.example"
	body := []byte{0x02, 0x00, 0x00}
	body = append(body, 0x00, byte(len(host)>>8), byte(len(host)))
	body = append(body, host...)
	full := append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)
	if got, ok := parseSNIExtension(full); !ok || got != host {
		t.Fatalf("mixed name types: got %q,%v want %q,true", got, ok, host)
	}
}
