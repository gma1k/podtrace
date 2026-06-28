package quicinitial

import (
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

	body := make([]byte, 2+32) // legacy_version + random
	body = append(body, 0x00)  // session_id len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites len=2 + one suite
	body = append(body, 0x01, 0x00)             // compression len=1 + null
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
