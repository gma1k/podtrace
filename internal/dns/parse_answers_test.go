package dns

import (
	"encoding/binary"
	"strings"
	"testing"
)

func aaaaRecord(ip [16]byte) []byte {
	r := []byte{0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10}
	return append(r, ip[:]...)
}

func cnameRecord(cname string) []byte {
	enc := encodeName(cname)
	r := []byte{0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c}
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(enc)))
	r = append(r, rdlen...)
	return append(r, enc...)
}

func TestParse_QDCountZero(t *testing.T) {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[2:4], 0x8180)
	binary.BigEndian.PutUint16(b[4:6], 0)
	binary.BigEndian.PutUint16(b[6:8], 0)

	m := Parse(b)
	if !m.Response {
		t.Error("response flag not set")
	}
	if m.Truncated {
		t.Error("qdcount==0 message must not be flagged truncated")
	}
	if m.QName != "" || len(m.Answers) != 0 {
		t.Errorf("expected no question/answers, got QName=%q answers=%d", m.QName, len(m.Answers))
	}
}

func TestParse_AAAAAnswer(t *testing.T) {
	ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	m := Parse(msg(0x1, 0x8180, "example.com", TypeAAAA, 1, aaaaRecord(ip)))
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answers))
	}
	if m.Answers[0].Type != TypeAAAA {
		t.Errorf("answer type = %d, want AAAA", m.Answers[0].Type)
	}
	if m.Answers[0].IP != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Errorf("AAAA IP = %q", m.Answers[0].IP)
	}
}

func TestParse_CNAMEAnswer(t *testing.T) {
	m := Parse(msg(0x1, 0x8180, "www.example.com", TypeA, 1, cnameRecord("example.com")))
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answers))
	}
	if m.Answers[0].Type != TypeCNAME {
		t.Errorf("answer type = %d, want CNAME", m.Answers[0].Type)
	}
	if m.Answers[0].CNAME != "example.com" {
		t.Errorf("CNAME = %q, want example.com", m.Answers[0].CNAME)
	}
	if m.Answers[0].IP != "" {
		t.Errorf("CNAME answer must carry no IP, got %q", m.Answers[0].IP)
	}
}

func TestParse_AnswerCountCappedAtMax(t *testing.T) {
	var answers []byte
	for i := 0; i < maxAnswers; i++ {
		answers = append(answers, aRecord([4]byte{10, 0, 0, byte(i)})...)
	}
	m := Parse(msg(0x1, 0x8180, "example.com", TypeA, 100, answers))
	if m.Truncated {
		t.Errorf("well-formed capped message must not be truncated: %+v", m)
	}
	if len(m.Answers) != maxAnswers {
		t.Fatalf("answers = %d, want the cap of %d", len(m.Answers), maxAnswers)
	}
}

func TestParse_SecondQuestionNameDecodeFails(t *testing.T) {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], 0x1)
	binary.BigEndian.PutUint16(b[2:4], 0x8180)
	binary.BigEndian.PutUint16(b[4:6], 2)
	binary.BigEndian.PutUint16(b[6:8], 0)
	b = append(b, encodeName("a.com")...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], TypeA)
	binary.BigEndian.PutUint16(q[2:4], 1)
	b = append(b, q...)
	b = append(b, 0x05)

	m := Parse(b)
	if !m.Truncated {
		t.Error("a second question whose name overruns the buffer must mark Truncated")
	}
}

func TestParse_SecondQuestionQTypeTruncated(t *testing.T) {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], 0x1)
	binary.BigEndian.PutUint16(b[2:4], 0x8180)
	binary.BigEndian.PutUint16(b[4:6], 2)
	binary.BigEndian.PutUint16(b[6:8], 0)
	b = append(b, encodeName("a.com")...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], TypeA)
	binary.BigEndian.PutUint16(q[2:4], 1)
	b = append(b, q...)
	b = append(b, encodeName("b")...)

	m := Parse(b)
	if !m.Truncated {
		t.Error("a second question truncated before its qtype must mark Truncated")
	}
}

func TestParse_TooManyLabels(t *testing.T) {
	labels := make([]string, 200)
	for i := range labels {
		labels[i] = "a"
	}
	m := Parse(msg(0x1, 0x0100, strings.Join(labels, "."), TypeA, 0, nil))
	if !m.Truncated {
		t.Error("a name exceeding the label limit must mark Truncated, not be accepted")
	}
	if m.QName != "" {
		t.Errorf("QName = %q, want empty on decode failure", m.QName)
	}
}

func TestResolvedIPs_SkipsCNAMEOnlyAnswers(t *testing.T) {
	r := Record{Msg: Message{Answers: []Answer{
		{Type: TypeCNAME, Name: "www.example.com", CNAME: "example.com"},
		{Type: TypeA, Name: "example.com", IP: "93.184.216.34"},
	}}}
	ips := r.ResolvedIPs()
	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Errorf("ResolvedIPs = %v, want only the A record (CNAME contributes no IP)", ips)
	}
}
