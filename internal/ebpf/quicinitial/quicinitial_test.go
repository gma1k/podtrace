package quicinitial

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestDeriveClientInitialKeys is the RFC 9001 Appendix A.1 known-answer vector:
// DCID 0x8394c8f03e515708 must derive these exact client Initial key/iv/hp.
func TestDeriveClientInitialKeys(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	k := DeriveClientInitialKeys(dcid)
	checks := []struct {
		name, got, want string
	}{
		{"key", hex.EncodeToString(k.Key), "1f369613dd76d5467730efcbe3b1a22d"},
		{"iv", hex.EncodeToString(k.IV), "fa044b2f42a3fd3b46fb255c"},
		{"hp", hex.EncodeToString(k.HP), "9f50449e04a0e810283a1e9933adedd2"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
}

// TestParseClientHelloSNI builds a minimal ClientHello carrying a server_name
// extension and checks extraction.
func TestParseClientHelloSNI(t *testing.T) {
	host := "example.com"
	// server_name extension body: list_len(2) | type(1)=0 | name_len(2) | name
	sni := []byte{0, 0}
	sni = append(sni, 0x00)
	sni = append(sni, byte(len(host)>>8), byte(len(host)))
	sni = append(sni, host...)
	binary.BigEndian.PutUint16(sni, uint16(len(sni)-2)) // list_len

	// one extension: type(2)=0x0000 | len(2) | sni
	ext := []byte{0x00, 0x00, byte(len(sni) >> 8), byte(len(sni))}
	ext = append(ext, sni...)

	body := make([]byte, 2+32)                             // legacy_version + random
	body = append(body, 0x00)                              // session_id len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01)            // cipher_suites len=2 + one suite
	body = append(body, 0x01, 0x00)                        // compression len=1 + null
	body = append(body, byte(len(ext)>>8), byte(len(ext))) // extensions len
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	got, ok := parseClientHelloSNI(hs)
	if !ok || got != host {
		t.Errorf("parseClientHelloSNI = %q,%v want %q,true", got, ok, host)
	}
}

func TestExtractSNINonInitial(t *testing.T) {
	if _, ok := ExtractSNI([]byte{0x40, 0, 0, 0}); ok {
		t.Error("short-header / non-initial should not parse")
	}
}

func TestReadVarint(t *testing.T) {
	cases := []struct {
		b    []byte
		want uint64
		n    int
		ok   bool
	}{
		{[]byte{0x25}, 0x25, 1, true},                                                         // 1-byte
		{[]byte{0x7b, 0xbd}, 15293, 2, true},                                                  // 2-byte
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4, true},                                  // 4-byte
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8, true}, // 8-byte
		{[]byte{}, 0, 0, false},                                                               // empty
		{[]byte{0x40}, 0, 0, false},                                                           // 2-byte prefix, truncated
	}
	for i, c := range cases {
		v, n, ok := readVarint(c.b, 0)
		if v != c.want || n != c.n || ok != c.ok {
			t.Errorf("case %d: readVarint=%d,%d,%v want %d,%d,%v", i, v, n, ok, c.want, c.n, c.ok)
		}
	}
	if _, _, ok := readVarint([]byte{0x01}, 5); ok {
		t.Error("offset past end should fail")
	}
}

func TestAsLen(t *testing.T) {
	if v, ok := asLen(1234); !ok || v != 1234 {
		t.Errorf("asLen(1234)=%d,%v", v, ok)
	}
	if _, ok := asLen(1<<20 + 1); ok {
		t.Error("asLen over 1MiB should fail")
	}
}

func TestParseSNIExtensionEdges(t *testing.T) {
	if _, ok := parseSNIExtension([]byte{0x00}); ok {
		t.Error("too short should fail")
	}
	d := []byte{0, 4, 0x02, 0, 1, 'x'} // list_len=4, type=2 (not host_name)
	if _, ok := parseSNIExtension(d); ok {
		t.Error("non host_name entry should not match")
	}
}

func buildClientInitial(t *testing.T, dcid, hs []byte) []byte {
	t.Helper()
	keys := DeriveClientInitialKeys(dcid)

	encVarint := func(v uint64) []byte {
		switch {
		case v < 64:
			return []byte{byte(v)}
		case v < 16384:
			return []byte{0x40 | byte(v>>8), byte(v)}
		default:
			return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
		}
	}

	crypto := []byte{0x06}
	crypto = append(crypto, encVarint(0)...)
	crypto = append(crypto, encVarint(uint64(len(hs)))...)
	crypto = append(crypto, hs...)
	payload := crypto

	const pnLen = 1
	length := pnLen + len(payload) + 16

	hdr := []byte{0xc0}
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x01)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00)
	hdr = append(hdr, 0x00)
	hdr = append(hdr, encVarint(uint64(length))...)
	pnOffset := len(hdr)
	hdr = append(hdr, 0x00)

	nonce := make([]byte, 12)
	copy(nonce, keys.IV)
	gcm, err := cipher.NewGCM(block2(keys.Key))
	if err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, payload, hdr)

	pkt := append(append([]byte{}, hdr...), ct...)

	block, err := aes.NewCipher(keys.HP)
	if err != nil {
		t.Fatal(err)
	}
	sampleOff := pnOffset + 4
	mask := make([]byte, 16)
	block.Encrypt(mask, pkt[sampleOff:sampleOff+16])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

func TestExtractSNIFullPacket(t *testing.T) {
	host := "example.org"
	sni := []byte{0, 0, 0x00}
	sni = append(sni, byte(len(host)>>8), byte(len(host)))
	sni = append(sni, host...)
	binary.BigEndian.PutUint16(sni, uint16(len(sni)-2))
	ext := []byte{0x00, 0x00, byte(len(sni) >> 8), byte(len(sni))}
	ext = append(ext, sni...)
	body := make([]byte, 2+32)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	pkt := buildClientInitial(t, dcid, hs)

	got, err := ExtractSNIErr(pkt)
	if err != nil {
		t.Fatalf("ExtractSNIErr error: %v", err)
	}
	if got != host {
		t.Errorf("ExtractSNIErr = %q, want %q", got, host)
	}
	if s, ok := ExtractSNI(pkt); !ok || s != host {
		t.Errorf("ExtractSNI = %q,%v want %q", s, ok, host)
	}
}

// buildClientInitialV is buildClientInitial for a chosen QUIC version: v2 uses
// its own salt/labels and Initial type bits 0b01 (RFC 9369).
func buildClientInitialV(t *testing.T, dcid, hs []byte, version uint32) []byte {
	t.Helper()
	keys := deriveClientInitialKeys(dcid, version)

	encVarint := func(v uint64) []byte {
		switch {
		case v < 64:
			return []byte{byte(v)}
		case v < 16384:
			return []byte{0x40 | byte(v>>8), byte(v)}
		default:
			return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
		}
	}

	crypto := []byte{0x06}
	crypto = append(crypto, encVarint(0)...)
	crypto = append(crypto, encVarint(uint64(len(hs)))...)
	crypto = append(crypto, hs...)
	payload := crypto

	const pnLen = 1
	length := pnLen + len(payload) + 16

	first := byte(0xc0)
	if version == VersionV2 {
		first = 0xd0
	}
	hdr := []byte{first}
	hdr = append(hdr, byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00)
	hdr = append(hdr, 0x00)
	hdr = append(hdr, encVarint(uint64(length))...)
	pnOffset := len(hdr)
	hdr = append(hdr, 0x00)

	nonce := make([]byte, 12)
	copy(nonce, keys.IV)
	gcm, err := cipher.NewGCM(block2(keys.Key))
	if err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, payload, hdr)

	pkt := append(append([]byte{}, hdr...), ct...)

	block, err := aes.NewCipher(keys.HP)
	if err != nil {
		t.Fatal(err)
	}
	sampleOff := pnOffset + 4
	mask := make([]byte, 16)
	block.Encrypt(mask, pkt[sampleOff:sampleOff+16])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

// buildClientHello assembles a minimal ClientHello handshake message carrying
// SNI and (optionally) ALPN extensions.
func buildClientHello(host string, alpn []string) []byte {
	var ext []byte
	if host != "" {
		sni := []byte{0, 0, 0x00}
		sni = append(sni, byte(len(host)>>8), byte(len(host)))
		sni = append(sni, host...)
		binary.BigEndian.PutUint16(sni, uint16(len(sni)-2))
		ext = append(ext, 0x00, 0x00, byte(len(sni)>>8), byte(len(sni)))
		ext = append(ext, sni...)
	}
	if len(alpn) > 0 {
		var list []byte
		for _, p := range alpn {
			list = append(list, byte(len(p)))
			list = append(list, p...)
		}
		body := []byte{byte(len(list) >> 8), byte(len(list))}
		body = append(body, list...)
		ext = append(ext, 0x00, 0x10, byte(len(body)>>8), byte(len(body)))
		ext = append(ext, body...)
	}
	body := make([]byte, 2+32)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func TestExtractV2FullPacket(t *testing.T) {
	hs := buildClientHello("v2.example.org", []string{"h3"})
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	pkt := buildClientInitialV(t, dcid, hs, VersionV2)

	info, err := Extract(pkt)
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	if info.SNI != "v2.example.org" || info.Version != VersionV2 {
		t.Fatalf("info = %+v", info)
	}
	if len(info.ALPN) != 1 || info.ALPN[0] != "h3" {
		t.Fatalf("ALPN = %v, want [h3]", info.ALPN)
	}
}

func TestExtractV1ALPN(t *testing.T) {
	hs := buildClientHello("example.org", []string{"h3", "h3-29"})
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pkt := buildClientInitialV(t, dcid, hs, VersionV1)

	info, err := Extract(pkt)
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	if info.SNI != "example.org" || info.Version != VersionV1 {
		t.Fatalf("info = %+v", info)
	}
	if len(info.ALPN) != 2 || info.ALPN[0] != "h3" || info.ALPN[1] != "h3-29" {
		t.Fatalf("ALPN = %v", info.ALPN)
	}
}

func TestExtractRejectsV1TypeBitsMismatch(t *testing.T) {
	hs := buildClientHello("example.org", nil)
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	pkt := buildClientInitialV(t, dcid, hs, VersionV1)
	pkt[0] = (pkt[0] &^ 0x30) | 0x10
	if _, err := Extract(pkt); err == nil {
		t.Fatal("expected v1 packet with 0-RTT type bits to be rejected")
	}
}

func TestDeriveV2KeysDifferFromV1(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	v1 := deriveClientInitialKeys(dcid, VersionV1)
	v2 := deriveClientInitialKeys(dcid, VersionV2)
	if bytes.Equal(v1.Key, v2.Key) || bytes.Equal(v1.HP, v2.HP) {
		t.Fatal("v2 Initial keys must differ from v1")
	}
}

// buildClientInitialChunk builds an Initial whose CRYPTO frame carries
// hs[off:off+n] at stream offset off.
func buildClientInitialChunk(t *testing.T, dcid, hs []byte, off, n int) []byte {
	t.Helper()
	chunk := hs[off : off+n]
	keys := deriveClientInitialKeys(dcid, VersionV1)

	encVarint := func(v uint64) []byte {
		switch {
		case v < 64:
			return []byte{byte(v)}
		case v < 16384:
			return []byte{0x40 | byte(v>>8), byte(v)}
		default:
			return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
		}
	}
	crypto := []byte{0x06}
	crypto = append(crypto, encVarint(uint64(off))...)
	crypto = append(crypto, encVarint(uint64(len(chunk)))...)
	crypto = append(crypto, chunk...)
	payload := crypto
	for len(payload) < 30 {
		payload = append(payload, 0x00)
	}

	const pnLen = 1
	length := pnLen + len(payload) + 16
	hdr := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00, 0x00)
	hdr = append(hdr, encVarint(uint64(length))...)
	pnOffset := len(hdr)
	hdr = append(hdr, 0x00)

	nonce := make([]byte, 12)
	copy(nonce, keys.IV)
	gcm, err := cipher.NewGCM(block2(keys.Key))
	if err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, payload, hdr)
	pkt := append(append([]byte{}, hdr...), ct...)

	block, err := aes.NewCipher(keys.HP)
	if err != nil {
		t.Fatal(err)
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

// TestExtractPacketsSplitClientHello covers quic-go's anti-DPI behavior: the
// ClientHello split across two Initial packets mid-SNI.
func TestExtractPacketsSplitClientHello(t *testing.T) {
	hs := buildClientHello("split.example.org", []string{"h3"})
	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	cut := len(hs) - 12 // split mid-SNI/ALPN tail
	pkt1 := buildClientInitialChunk(t, dcid, hs, 0, cut)
	pkt2 := buildClientInitialChunk(t, dcid, hs, cut, len(hs)-cut)

	if info, err := ExtractPackets([][]byte{pkt1}); err == nil {
		t.Fatalf("single split packet must not extract successfully, got %+v", info)
	}
	info, err := ExtractPackets([][]byte{pkt1, pkt2})
	if err != nil {
		t.Fatalf("ExtractPackets: %v", err)
	}
	if info.SNI != "split.example.org" || len(info.ALPN) != 1 || info.ALPN[0] != "h3" {
		t.Fatalf("info = %+v", info)
	}
	// Reversed arrival order must also work.
	info, err = ExtractPackets([][]byte{pkt2, pkt1})
	if err != nil || info.SNI != "split.example.org" {
		t.Fatalf("reversed order: info=%+v err=%v", info, err)
	}
}
