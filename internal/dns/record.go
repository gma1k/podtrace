package dns

import "encoding/binary"

const recordHeaderSize = 64

// Record is a decoded DNS payload ringbuf entry: the BPF-supplied metadata plus
// the fully parsed DNS message.
type Record struct {
	CgroupID  uint64
	Timestamp uint64
	LatencyNS uint64
	PID       uint32
	ServerIP  uint32
	ServerIP6 [16]byte
	TxID      uint16
	QType     uint16
	Transport uint8
	IsV6      bool
	RCode     uint8
	Msg       Message
}

// ParseRecord splits the fixed metadata header from the trailing raw DNS
// message and decodes the message with Parse.
func ParseRecord(data []byte) (Record, bool) {
	if len(data) < recordHeaderSize {
		return Record{}, false
	}
	payloadLen := int(binary.LittleEndian.Uint16(data[52:54]))
	end := recordHeaderSize + payloadLen
	if payloadLen < 0 || end > len(data) {
		return Record{}, false
	}

	var r Record
	r.CgroupID = binary.LittleEndian.Uint64(data[0:8])
	r.Timestamp = binary.LittleEndian.Uint64(data[8:16])
	r.LatencyNS = binary.LittleEndian.Uint64(data[16:24])
	r.PID = binary.LittleEndian.Uint32(data[24:28])
	r.ServerIP = binary.LittleEndian.Uint32(data[28:32])
	copy(r.ServerIP6[:], data[32:48])
	r.TxID = binary.LittleEndian.Uint16(data[48:50])
	r.QType = binary.LittleEndian.Uint16(data[50:52])
	r.Transport = data[54]
	r.IsV6 = data[55] != 0
	r.RCode = data[56]
	r.Msg = Parse(data[recordHeaderSize:end])
	return r, true
}

// ResolvedIPs returns the unique A/AAAA answer addresses in the message, in
// first-seen order. CNAME-only answers contribute no IPs.
func (r Record) ResolvedIPs() []string {
	seen := make(map[string]struct{}, len(r.Msg.Answers))
	var ips []string
	for _, a := range r.Msg.Answers {
		if a.IP == "" {
			continue
		}
		if _, dup := seen[a.IP]; dup {
			continue
		}
		seen[a.IP] = struct{}{}
		ips = append(ips, a.IP)
	}
	return ips
}
