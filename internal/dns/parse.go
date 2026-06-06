// Package dns parses DNS wire-format messages in userspace.
package dns

import "encoding/binary"

const (
	TypeA     = 1
	TypeCNAME = 5
	TypeAAAA  = 28
)

const (
	maxNameLabels = 127
	maxAnswers    = 64
	headerLen     = 12
)

type Answer struct {
	Type  uint16
	Name  string
	IP    string
	CNAME string
}

type Message struct {
	ID        uint16
	Response  bool
	RCode     uint8
	QName     string
	QType     uint16
	Answers   []Answer
	Truncated bool
}

func Parse(b []byte) Message {
	var m Message
	if len(b) < headerLen {
		m.Truncated = true
		return m
	}
	m.ID = binary.BigEndian.Uint16(b[0:2])
	flags := binary.BigEndian.Uint16(b[2:4])
	m.Response = flags&0x8000 != 0
	m.RCode = uint8(flags & 0x000f)
	qdcount := binary.BigEndian.Uint16(b[4:6])
	ancount := binary.BigEndian.Uint16(b[6:8])

	off := headerLen
	if qdcount == 0 {
		return m
	}

	name, next, ok := decodeName(b, off)
	if !ok {
		m.Truncated = true
		return m
	}
	m.QName = name
	off = next
	if off+4 > len(b) {
		m.Truncated = true
		return m
	}
	m.QType = binary.BigEndian.Uint16(b[off : off+2])
	off += 4

	limit := int(ancount)
	if limit > maxAnswers {
		limit = maxAnswers
	}
	for i := 0; i < limit; i++ {
		name, next, ok := decodeName(b, off)
		if !ok {
			m.Truncated = true
			return m
		}
		off = next
		if off+10 > len(b) {
			m.Truncated = true
			return m
		}
		atype := binary.BigEndian.Uint16(b[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdlen > len(b) {
			m.Truncated = true
			return m
		}
		ans := Answer{Type: atype, Name: name}
		switch atype {
		case TypeA:
			if rdlen == 4 {
				ans.IP = ipv4String(b[off : off+4])
			}
		case TypeAAAA:
			if rdlen == 16 {
				ans.IP = ipv6String(b[off : off+16])
			}
		case TypeCNAME:
			if cname, _, ok := decodeName(b, off); ok {
				ans.CNAME = cname
			}
		}
		m.Answers = append(m.Answers, ans)
		off += rdlen
	}
	return m
}

func decodeName(b []byte, off int) (string, int, bool) {
	var out []byte
	next := -1
	jumps := 0
	labels := 0
	for {
		if off < 0 || off >= len(b) {
			return "", 0, false
		}
		c := b[off]
		if c&0xc0 == 0xc0 { // compression pointer
			if off+1 >= len(b) {
				return "", 0, false
			}
			if next == -1 {
				next = off + 2
			}
			jumps++
			if jumps > maxNameLabels {
				return "", 0, false
			}
			off = int(uint16(c&0x3f)<<8 | uint16(b[off+1]))
			continue
		}
		if c == 0 {
			off++
			if next == -1 {
				next = off
			}
			return string(out), next, true
		}
		labels++
		if labels > maxNameLabels {
			return "", 0, false
		}
		start := off + 1
		end := start + int(c)
		if end > len(b) {
			return "", 0, false
		}
		if len(out) > 0 {
			out = append(out, '.')
		}
		out = append(out, b[start:end]...)
		off = end
	}
}

func ipv4String(b []byte) string {
	return itoa(b[0]) + "." + itoa(b[1]) + "." + itoa(b[2]) + "." + itoa(b[3])
}

func ipv6String(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 39)
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[b[i]>>4], hex[b[i]&0xf], hex[b[i+1]>>4], hex[b[i+1]&0xf])
	}
	return string(out)
}

func itoa(v byte) string {
	if v == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = '0' + v%10
		v /= 10
	}
	return string(buf[i:])
}
