package dns

import (
	"encoding/binary"
	"testing"
)

func msg(id, flags uint16, qname string, qtype uint16, ancount uint16, answers []byte) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], 1) // qdcount
	binary.BigEndian.PutUint16(b[6:8], ancount)
	b = append(b, encodeName(qname)...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], qtype)
	binary.BigEndian.PutUint16(q[2:4], 1) // IN
	b = append(b, q...)
	return append(b, answers...)
}

func encodeName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func aRecord(ip [4]byte) []byte {
	r := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04}
	return append(r, ip[:]...)
}

func TestParse_Query(t *testing.T) {
	m := Parse(msg(0x1234, 0x0100, "example.com", TypeA, 0, nil))
	if m.Response {
		t.Error("query parsed as response")
	}
	if m.QName != "example.com" {
		t.Errorf("QName = %q, want example.com", m.QName)
	}
	if m.QType != TypeA {
		t.Errorf("QType = %d, want %d", m.QType, TypeA)
	}
}

func TestParse_ResponseWithA(t *testing.T) {
	ans := aRecord([4]byte{93, 184, 216, 34})
	m := Parse(msg(0x1234, 0x8180, "example.com", TypeA, 1, ans))
	if !m.Response {
		t.Error("response not flagged")
	}
	if m.RCode != 0 {
		t.Errorf("RCode = %d, want 0 (NOERROR)", m.RCode)
	}
	if len(m.Answers) != 1 || m.Answers[0].IP != "93.184.216.34" {
		t.Fatalf("answers = %+v, want one A 93.184.216.34", m.Answers)
	}
	if m.Answers[0].Name != "example.com" {
		t.Errorf("answer name = %q (compression not resolved)", m.Answers[0].Name)
	}
}

func TestParse_NXDOMAIN(t *testing.T) {
	m := Parse(msg(0x1234, 0x8183, "doesnotexist.invalid", TypeA, 0, nil))
	if m.RCode != 3 {
		t.Errorf("RCode = %d, want 3 (NXDOMAIN)", m.RCode)
	}
}

func TestParse_Truncated(t *testing.T) {
	full := msg(0x1234, 0x8180, "example.com", TypeA, 1, aRecord([4]byte{1, 2, 3, 4}))
	for n := 0; n < len(full); n++ {
		m := Parse(full[:n])
		_ = m
	}
}

func TestParse_PointerLoop(t *testing.T) {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = append(b, 0xc0, 0x0c)
	m := Parse(b)
	if !m.Truncated {
		t.Error("self-referential pointer should mark Truncated, not hang")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(msg(0x1, 0x0100, "example.com", TypeA, 0, nil))
	f.Add(msg(0x2, 0x8180, "a.b.c.example.com", TypeAAAA, 1, aRecord([4]byte{8, 8, 8, 8})))
	f.Add([]byte{0xc0, 0x0c})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Parse(data)
	})
}