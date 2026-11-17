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

	for q := 1; q < int(qdcount); q++ {
		_, next, ok := decodeName(b, off)
		if !ok {
			m.Truncated = true
			return m
		}
		off = next
		if off+4 > len(b) {
			m.Truncated = true
			return m
		}
		off += 4
	}

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
		atype, rdata, after, ok := resourceRecord(b, next)
		if !ok {
			m.Truncated = true
			return m
		}
		off = after
		ans := Answer{Type: atype, Name: name}
		switch atype {
		case TypeA:
			if len(rdata) == 4 {
				ans.IP = ipv4String([4]byte(rdata))
			}
		case TypeAAAA:
			if len(rdata) == 16 {
				ans.IP = ipv6String([16]byte(rdata))
			}
		case TypeCNAME:
			if cname, _, ok := decodeName(b, off-len(rdata)); ok {
				ans.CNAME = cname
			}
		}
		m.Answers = append(m.Answers, ans)
	}
	return m
}

// resourceRecord reads the fixed fields of the resource record whose name
// ends at off: its type and its data, with the offset just past that data.
func resourceRecord(b []byte, off int) (atype uint16, rdata []byte, next int, ok bool) {
	dataStart := off + 10
	if off < 0 || dataStart > len(b) {
		return 0, nil, 0, false
	}
	fixed := [10]byte(b[off:dataStart])
	next = dataStart + int(binary.BigEndian.Uint16(fixed[8:10]))
	if next > len(b) {
		return 0, nil, 0, false
	}
	return binary.BigEndian.Uint16(fixed[0:2]), b[dataStart:next], next, true
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

func ipv4String(b [4]byte) string {
	return itoa(b[0]) + "." + itoa(b[1]) + "." + itoa(b[2]) + "." + itoa(b[3])
}

func ipv6String(b [16]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 39)
	for i, v := range b {
		if i > 0 && i%2 == 0 {
			out = append(out, ':')
		}
		out = append(out, hex[v>>4], hex[v&0xf])
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
