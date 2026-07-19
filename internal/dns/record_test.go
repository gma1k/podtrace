package dns

import (
	"encoding/binary"
	"testing"
)

func payloadRecord(hdr map[string]any, payload []byte) []byte {
	b := make([]byte, recordHeaderSize+len(payload))
	if v, ok := hdr["cgroup"].(uint64); ok {
		binary.LittleEndian.PutUint64(b[0:8], v)
	}
	if v, ok := hdr["ts"].(uint64); ok {
		binary.LittleEndian.PutUint64(b[8:16], v)
	}
	if v, ok := hdr["latency"].(uint64); ok {
		binary.LittleEndian.PutUint64(b[16:24], v)
	}
	if v, ok := hdr["pid"].(uint32); ok {
		binary.LittleEndian.PutUint32(b[24:28], v)
	}
	if v, ok := hdr["serverip"].(uint32); ok {
		binary.LittleEndian.PutUint32(b[28:32], v)
	}
	if v, ok := hdr["txid"].(uint16); ok {
		binary.LittleEndian.PutUint16(b[48:50], v)
	}
	if v, ok := hdr["qtype"].(uint16); ok {
		binary.LittleEndian.PutUint16(b[50:52], v)
	}
	binary.LittleEndian.PutUint16(b[52:54], uint16(len(payload)))
	if v, ok := hdr["transport"].(uint8); ok {
		b[54] = v
	}
	if v, ok := hdr["isv6"].(uint8); ok {
		b[55] = v
	}
	if v, ok := hdr["rcode"].(uint8); ok {
		b[56] = v
	}
	copy(b[recordHeaderSize:], payload)
	return b
}

func TestParseRecord_HeaderAndAnswers(t *testing.T) {
	answers := append(aRecord([4]byte{93, 184, 216, 34}), aRecord([4]byte{93, 184, 216, 35})...)
	payload := msg(0x1234, 0x8180, "example.com", TypeA, 2, answers)
	buf := payloadRecord(map[string]any{
		"cgroup":    uint64(0xABCD),
		"latency":   uint64(1_500_000),
		"pid":       uint32(4242),
		"serverip":  uint32(0x0808080A),
		"txid":      uint16(0x1234),
		"qtype":     uint16(TypeA),
		"transport": uint8(1),
		"rcode":     uint8(0),
	}, payload)

	r, ok := ParseRecord(buf)
	if !ok {
		t.Fatal("ParseRecord returned !ok for a well-formed record")
	}
	if r.CgroupID != 0xABCD || r.PID != 4242 || r.LatencyNS != 1_500_000 {
		t.Errorf("header mismatch: cgroup=%x pid=%d latency=%d", r.CgroupID, r.PID, r.LatencyNS)
	}
	if r.TxID != 0x1234 || r.QType != TypeA || r.Transport != 1 || r.RCode != 0 {
		t.Errorf("header mismatch: txid=%x qtype=%d transport=%d rcode=%d", r.TxID, r.QType, r.Transport, r.RCode)
	}
	if r.ServerIP != 0x0808080A {
		t.Errorf("ServerIP = %x, want 0808080A", r.ServerIP)
	}
	if r.Msg.QName != "example.com" {
		t.Errorf("QName = %q, want example.com", r.Msg.QName)
	}
	if len(r.Msg.Answers) != 2 {
		t.Fatalf("answers = %d, want 2 (userspace parse must see all, not just the first)", len(r.Msg.Answers))
	}
	ips := r.ResolvedIPs()
	if len(ips) != 2 || ips[0] != "93.184.216.34" || ips[1] != "93.184.216.35" {
		t.Errorf("ResolvedIPs = %v, want both A records in order", ips)
	}
}

func TestParseRecord_ResolvedIPsDedup(t *testing.T) {
	answers := append(aRecord([4]byte{10, 0, 0, 1}), aRecord([4]byte{10, 0, 0, 1})...)
	payload := msg(0x1, 0x8180, "dup.example", TypeA, 2, answers)
	buf := payloadRecord(map[string]any{"qtype": uint16(TypeA)}, payload)

	r, ok := ParseRecord(buf)
	if !ok {
		t.Fatal("ParseRecord !ok")
	}
	if ips := r.ResolvedIPs(); len(ips) != 1 || ips[0] != "10.0.0.1" {
		t.Errorf("ResolvedIPs = %v, want single deduplicated 10.0.0.1", ips)
	}
}

func TestParseRecord_ShortHeader(t *testing.T) {
	if _, ok := ParseRecord(make([]byte, recordHeaderSize-1)); ok {
		t.Error("ParseRecord accepted a buffer shorter than the header")
	}
}

func TestParseRecord_PayloadLenOverrun(t *testing.T) {
	buf := make([]byte, recordHeaderSize+4)
	binary.LittleEndian.PutUint16(buf[52:54], 1000)
	if _, ok := ParseRecord(buf); ok {
		t.Error("ParseRecord accepted a record whose payload_len overruns the buffer")
	}
}

func TestParseRecord_EmptyPayload(t *testing.T) {
	buf := payloadRecord(map[string]any{"pid": uint32(7)}, nil)
	r, ok := ParseRecord(buf)
	if !ok {
		t.Fatal("header-only record should parse ok")
	}
	if r.PID != 7 || len(r.ResolvedIPs()) != 0 {
		t.Errorf("unexpected: pid=%d ips=%v", r.PID, r.ResolvedIPs())
	}
}
